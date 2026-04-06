"""
Celery Scan Tasks — Complete Integrated Pipeline
=================================================

EXACT FLOW:
  1. subfinder discovers subdomains from root domain
  2. _clean_domain() strips URLs, http://, trailing slashes
  3. CT log cache built ONCE per root domain (local crt.txt → live API)
  4. For each domain:
     PATH A  — nmap open → TLS direct → openssl → real leaf cert algo
     PATH B1 — nmap blocked → CT SANs → origin IP/host → TLS+SNI bypass → real algo ✓✓
     PATH B2 — no origin IP → CT expiry stored, algorithm approximate (issuer inference)
     PATH C  — no data anywhere → RSA-2048 conservative default
  5. HNDL = algo×0.40 + keysize×0.20 + sensitivity×0.20 + tls_version×0.10 + expiry×0.10
  6. Finding + Remediation + ComplianceTag saved to DB
  7. CBOM generated in CycloneDX 1.4 format
"""
import uuid
import re
import os
from datetime import datetime
from urllib.parse import urlparse
from celery import shared_task
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models.models import (
    ScanJob, Asset, Certificate, CipherSuite, Finding,
    Remediation, CBOM, ComplianceTag,
    ScanStatus, ProtocolType, FindingType, PQCReadiness
)
from app.scanning.scanner import scan_asset, run_subfinder, scan_via_origin_bypass
from app.scanning.ct_log_scanner import (
    get_domains_from_ct_logs, parse_ct_log_file, find_origin_targets_from_ct,
    get_historical_ips_viewdns, get_ips_from_spf, _is_known_cdn_ip,
)
from app.engines.hndl_engine import (
    calculate_hndl_score, is_quantum_vulnerable,
    get_pqc_readiness_label, is_pqc_ready,
    get_algorithm_vulnerability_score
)
from app.engines.compliance_engine import map_finding_to_compliance
from app.engines.ai_remediation import get_remediation_playbook
from app.engines.cbom_generator import generate_cbom
import logging

logger = logging.getLogger(__name__)

# ── Path to the local crt.txt export from crt.sh ─────────────────
# Mounted into the Docker container via volume or placed alongside this file.
_CRT_TXT_PATH = os.environ.get(
    "CRT_TXT_PATH",
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "crt.txt")
)


# ─────────────────────────────────────────────────────────────────
# DOMAIN UTILITIES
# ─────────────────────────────────────────────────────────────────

def _clean_domain(raw: str) -> str:
    """Strip http://, paths, trailing slashes. Nmap needs a bare domain/IP."""
    raw = raw.strip()
    if not raw:
        return ""
    if raw.startswith("http://") or raw.startswith("https://"):
        return urlparse(raw).netloc.lower()
    return raw.rstrip("/").split("/")[0].split("?")[0].lower()


def _get_root_domain(domain: str) -> str:
    """
    Derive the root domain used for CT log lookup.
      netbanking.pnb.bank.in → pnb.bank.in   (4-part → last 3)
      api.example.com        → example.com    (3-part → last 2)
    """
    parts = domain.split(".")
    if len(parts) >= 4:
        return ".".join(parts[-3:])    # e.g. pnb.bank.in
    if len(parts) >= 3:
        return ".".join(parts[-2:])    # e.g. example.com
    return domain


# ─────────────────────────────────────────────────────────────────
# CT LOG CACHE — built ONCE, shared across all domains in a scan
# ─────────────────────────────────────────────────────────────────

def _build_ct_cache(root_domain: str) -> dict:
    """
    Query crt.sh ONCE for a root domain.
    Returns {subdomain_lower: {algorithm, key_size, expires_at, issuer, source}}.

    Strategy:
      1. Try the local crt.txt file first (instant, offline)
      2. Fall back to live crt.sh API
    This way the file acts as a warm cache and the API is only hit when needed.
    """
    cache: dict = {}

    # ── Try local crt.txt first ───────────────────────────────────
    crt_path = os.path.abspath(_CRT_TXT_PATH)
    if os.path.isfile(crt_path):
        logger.info(f"CT cache: loading from local file {crt_path}")
        entries = parse_ct_log_file(crt_path)
        # Filter to entries that belong to this root domain
        for e in entries:
            d = e.get("domain", "").lower()
            if d and (d == root_domain or d.endswith("." + root_domain)):
                cache[d] = e
        logger.info(f"CT cache (file): {len(cache)} entries for {root_domain}")
        if cache:
            return cache

    # ── Fall back to live crt.sh API ─────────────────────────────
    logger.info(f"CT cache: querying crt.sh API for {root_domain}")
    entries = get_domains_from_ct_logs(root_domain)
    for e in entries:
        d = e.get("domain", "").lower()
        if d:
            cache[d] = e
    logger.info(f"CT cache (API): {len(cache)} entries for {root_domain}")
    return cache


# ─────────────────────────────────────────────────────────────────
# MAIN CELERY TASK
# ─────────────────────────────────────────────────────────────────

@shared_task(bind=True, name="app.tasks.scan_tasks.run_full_scan", max_retries=2)
def run_full_scan(self, scan_id: str, full_scan: bool = True):

    db: Session = SessionLocal()
    scan_job = None

    try:
        scan_job = db.query(ScanJob).filter(ScanJob.scan_id == scan_id).first()
        if not scan_job:
            logger.error(f"ScanJob {scan_id} not found")
            return

        scan_job.status = ScanStatus.RUNNING
        scan_job.started_at = datetime.utcnow()
        db.commit()

        targets = scan_job.target_assets or []

        # ── STEP 1: Clean input targets ───────────────────────────
        self.update_state(state="PROGRESS", meta={"progress": 3, "step": "Cleaning targets"})
        clean_targets = list(set(
            _clean_domain(t) for t in targets if _clean_domain(t)
        ))
        logger.info(f"Clean targets: {clean_targets}")

        # ── STEP 2: subfinder — discover subdomains (only if full_scan) ───
        if full_scan:
            self.update_state(state="PROGRESS", meta={"progress": 5, "step": "Discovering subdomains (subfinder)"})
            expanded = []
            root_domains = set()
            
            for target in clean_targets:
                # IP addresses: scan directly, no subfinder
                if re.match(r"^\d+\.\d+\.\d+\.\d+$", target):
                    expanded.append(target)
                else:
                    root_domains.add(_get_root_domain(target))
                    expanded.append(target)
                    
            for root in root_domains:
                try:
                    subs = run_subfinder(root)
                    for sub in subs:
                        cleaned = _clean_domain(sub)
                        if cleaned and "." in cleaned:
                            expanded.append(cleaned)
                except Exception as e:
                    logger.warning(f"Subfinder failed for {root}: {e}")

            all_domains = list(set(expanded))
            logger.info(f"subfinder discovered {len(all_domains)} unique domains from {len(root_domains)} root(s)")
        else:
            self.update_state(state="PROGRESS", meta={"progress": 5, "step": "Targeted scan — skipping subdomain discovery"})
            all_domains = clean_targets
            logger.info(f"Targeted scan (full_scan=False): {len(all_domains)} domains")

        # ── STEP 3: Build CT log cache ONCE per root domain ───────
        # crt.sh gives us algorithm + expiry for ALL subdomains —
        # even CDN-protected and firewall-blocked ones.
        self.update_state(state="PROGRESS", meta={"progress": 8, "step": "Building CT log cache"})
        ct_cache: dict = {}
        seen_roots: set = set()
        for target in clean_targets:
            root = _get_root_domain(target)
            if root not in seen_roots:
                seen_roots.add(root)
                ct_cache.update(_build_ct_cache(root))
        logger.info(f"CT cache total: {len(ct_cache)} entries across {len(seen_roots)} root domain(s)")

        # ── STEP 4: Scan each domain ──────────────────────────────
        total = len(all_domains)
        processed_assets = []

        for i, domain in enumerate(all_domains):

            # Close and recreate db session to prevent cross-domain pollution/corruption if rollback hits
            db.close()
            db = SessionLocal()
            scan_job = db.query(ScanJob).filter(ScanJob.scan_id == scan_id).first()

            progress = int(10 + (i / max(total, 1)) * 78)
            self.update_state(state="PROGRESS", meta={
                "progress": progress,
                "step":     f"Scanning {domain} ({i+1}/{total})"
            })
            if scan_job:
                scan_job.progress = progress
                db.commit()

            try:
                # 4a: Network scan (nmap + TLS via openssl / python ssl)
                scan_data    = scan_asset(domain)
                protocol     = scan_data.get("protocol", "UNKNOWN")
                tls_data     = scan_data.get("tls_data", {})
                open_ports   = scan_data.get("open_ports", [])
                resolved_ips = scan_data.get("resolved_ips", [])
                is_cdn       = scan_data.get("is_cdn", False)

                # 4b: Three-path algorithm decision ──────────────────
                #
                # PATH A: TLS handshake succeeded → openssl gave us the real algo
                # PATH B: TLS blocked             → use CT log cache (passive recon)
                # PATH C: No data at all          → conservative RSA-2048 default
                #
                main_algorithm   = None
                main_key_size    = None
                expires_at       = None
                algorithm_source = "default"

                # PATH A — check TLS scan result
                tls_algo     = tls_data.get("algorithm")       # set by openssl_tls_scan
                tls_key_size = tls_data.get("key_size")

                # Also scan certificates list for algo/key_size
                for cert_data in scan_data.get("certificates", []):
                    c_algo = cert_data.get("algorithm")
                    c_ks   = cert_data.get("key_size")
                    if c_algo and main_algorithm is None:
                        main_algorithm = c_algo
                        algorithm_source = tls_data.get("algorithm_source", "tls_scan")
                    if c_ks and main_key_size is None:
                        main_key_size = c_ks
                    # Parse expiry from TLS cert
                    not_after_str = cert_data.get("notAfter", "")
                    if not_after_str and expires_at is None:
                        for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y"):
                            try:
                                expires_at = datetime.strptime(not_after_str.strip(), fmt)
                                break
                            except Exception:
                                continue

                if tls_algo and main_algorithm is None:
                    main_algorithm   = tls_algo
                    main_key_size    = tls_key_size or main_key_size
                    algorithm_source = tls_data.get("scan_method", "tls_scan")

                if main_algorithm:
                    logger.info(f"{domain}: [PATH A] TLS direct → {main_algorithm}-{main_key_size} [{algorithm_source}]")

                else:
                    # ── PATH B1: CT SANs → origin IP bypass → REAL leaf cert algo ──────
                    # crt.sh may list an origin IP or internal host in the cert SANs.
                    # Connecting to that IP with SNI=domain bypasses the WAF/CDN
                    # and returns the ACTUAL leaf certificate.
                    bypass_done = False
                    try:
                        origin_targets = find_origin_targets_from_ct(domain)

                        # Fix 7a: Add SPF-mined IPs (data: REAL)
                        spf_ips = get_ips_from_spf(domain)
                        for ip in spf_ips:
                            origin_targets.append({
                                "type": "ip", "value": ip,
                                "cert_domain": domain, "source": "spf",
                            })

                        # Fix 7b: Add historical DNS IPs (data: APPROX)
                        hist_ips = get_historical_ips_viewdns(_get_root_domain(domain))
                        for ip in hist_ips:
                            if not _is_known_cdn_ip(ip):
                                origin_targets.append({
                                    "type": "ip", "value": ip,
                                    "cert_domain": domain, "source": "passive_dns",
                                })

                        # Limit origin targets to avoid excessive scanning
                        import time as _time
                        _b1_start = _time.time()
                        _B1_TIME_BUDGET = 90   # seconds for ALL bypass attempts
                        _B1_MAX_TARGETS = 3     # try at most 3 origin IPs

                        for idx, target in enumerate(origin_targets[:_B1_MAX_TARGETS]):
                            # Enforce time budget
                            if _time.time() - _b1_start > _B1_TIME_BUDGET:
                                logger.info(f"{domain}: [PATH B1] time budget exhausted, stopping bypass")
                                break

                            t_value = target.get("value", "")
                            if not t_value:
                                continue
                            t_source = target.get("source", "ct_san")
                            logger.info(
                                f"{domain}: [PATH B1] trying origin bypass via "
                                f"{target['type']}={t_value} (source={t_source})"
                            )
                            bypass_data = scan_via_origin_bypass(
                                sni_domain=domain,
                                origin_target=t_value,
                                # Fix 5: omit port — multi-port probing via BYPASS_PORTS
                            )
                            bypass_certs = bypass_data.get("certificates", [])
                            if bypass_certs:
                                c = bypass_certs[0]
                                b_algo = c.get("algorithm")
                                b_ks   = c.get("key_size")
                                if b_algo:
                                    main_algorithm   = b_algo
                                    main_key_size    = b_ks or 2048
                                    algorithm_source = f"origin_bypass_{t_source}"
                                    # Parse expiry from bypass cert
                                    not_after_str = c.get("notAfter", "")
                                    if not_after_str and expires_at is None:
                                        for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y"):
                                            try:
                                                expires_at = datetime.strptime(not_after_str.strip(), fmt)
                                                break
                                            except Exception:
                                                continue
                                    # Also pull into scan_data so cert records are saved
                                    scan_data["certificates"] = bypass_certs
                                    scan_data["cipher_suites"] = bypass_data.get("cipher_suites", [])
                                    bypass_done = True
                                    logger.info(
                                        f"{domain}: [PATH B1] ✓ origin bypass succeeded → "
                                        f"{main_algorithm}-{main_key_size} via {t_value} "
                                        f"(source={t_source}, port={bypass_data.get('port', '?')})"
                                    )
                                    break
                    except Exception as e:
                        logger.debug(f"{domain}: PATH B1 error: {e}")

                    if not bypass_done:
                        # ── PATH B2: CT cache → expiry stored, algo is issuer-inferred ──
                        # NOTE: This is an APPROXIMATION. The algo comes from the CA's
                        # name, not the leaf cert. Use only when bypass also failed.
                        ct_entry = ct_cache.get(domain.lower())
                        if ct_entry:
                            main_algorithm   = ct_entry.get("algorithm", "RSA")
                            main_key_size    = ct_entry.get("key_size", 2048)
                            expires_at       = expires_at or ct_entry.get("expires_at")
                            algorithm_source = "ct_logs_issuer_inferred"
                            logger.info(
                                f"{domain}: [PATH B2] CT issuer-inferred → {main_algorithm}-{main_key_size} "
                                f"(approx) expires={expires_at} issuer={ct_entry.get('issuer', 'Unknown')}"
                            )
                        else:
                            # ── PATH C: nothing → conservative default ──────────────────
                            main_algorithm   = "RSA"
                            main_key_size    = 2048
                            algorithm_source = "default"
                            logger.info(f"{domain}: [PATH C] default → RSA-2048 (no TLS + no CT data)")

                # ── Final values ──────────────────────────────────
                final_algo     = main_algorithm or "RSA"
                final_key_size = main_key_size  or 2048
                sensitivity    = _get_data_sensitivity(domain)

                # Fix for protocol UNKNOWN: If TLS/Bypass cipher suites exist, deduce protocol from port
                if protocol == "UNKNOWN":
                    if scan_data.get("cipher_suites"):
                        _p = scan_data["cipher_suites"][0].get("port")
                        if _p in [443, 8443, 8080]: protocol = "HTTPS"
                        elif _p in [465, 587, 25]: protocol = "SMTP"
                        elif _p in [993, 143]: protocol = "IMAP"
                        elif _p in [995, 110]: protocol = "POP3"
                        elif _p in [21, 990]: protocol = "FTPS"

                # Extract TLS version for HNDL scoring
                tls_version_str = tls_data.get("tls_version") or None

                # Unpack tuple returned by calculate_hndl_score
                asset_hndl_result = calculate_hndl_score(
                    final_algo, final_key_size, sensitivity, expires_at, tls_version_str
                )
                asset_hndl = asset_hndl_result[0] if isinstance(asset_hndl_result, tuple) else asset_hndl_result
                hndl_breakdown = asset_hndl_result[1] if isinstance(asset_hndl_result, tuple) else {}

                pqc_label  = get_pqc_readiness_label(asset_hndl)

                # 4c: Save Asset ───────────────────────────────────
                asset = Asset(
                    asset_id=str(uuid.uuid4()),
                    scan_id=scan_id,
                    domain=domain,
                    resolved_ips=resolved_ips,
                    protocol=_map_protocol(protocol),
                    is_cdn=is_cdn,
                    cdn_provider=scan_data.get("cdn_provider"),
                    server_software=scan_data.get("server_software"),
                    open_ports=open_ports,
                    service_category=_get_service_category(protocol, domain, scan_data.get("server_software")),
                    hndl_score=asset_hndl,
                    hndl_breakdown=hndl_breakdown,
                    is_pqc=is_pqc_ready(final_algo),
                    pqc_readiness=_map_pqc_readiness(pqc_label),
                    scan_method=algorithm_source,  # track which path was used
                )
                db.add(asset)
                db.flush()

                # 4d: Save Certificate(s) ──────────────────────────
                ct_entry_for_cert = ct_cache.get(domain.lower(), {})

                if scan_data.get("certificates"):
                    for cert_data in scan_data["certificates"]:
                        subj = cert_data.get("subject", {})
                        iss  = cert_data.get("issuer", {})
                        db.add(Certificate(
                            cert_id    = str(uuid.uuid4()),
                            asset_id   = asset.asset_id,
                            domain     = domain,
                            subject    = (
                                subj.get("commonName", domain)
                                if isinstance(subj, dict) else str(subj) or domain
                            ),
                            issuer     = (
                                iss.get("organizationName") or iss.get("commonName") or "Unknown"
                                if isinstance(iss, dict) else str(iss) or "Unknown"
                            ),
                            algorithm  = final_algo,
                            key_size   = final_key_size,
                            hndl_score = asset_hndl,
                            expires_at = expires_at,
                            is_pqc     = is_pqc_ready(final_algo),
                        ))
                elif ct_entry_for_cert:
                    # PATH B: synthesise a certificate record from CT log data
                    db.add(Certificate(
                        cert_id    = str(uuid.uuid4()),
                        asset_id   = asset.asset_id,
                        domain     = domain,
                        subject    = domain,
                        issuer     = ct_entry_for_cert.get("issuer", "Unknown"),
                        algorithm  = final_algo,
                        key_size   = final_key_size,
                        hndl_score = asset_hndl,
                        expires_at = expires_at,
                        is_pqc     = is_pqc_ready(final_algo),
                    ))
                else:
                    # PATH C: minimal record — mark as default
                    db.add(Certificate(
                        cert_id    = str(uuid.uuid4()),
                        asset_id   = asset.asset_id,
                        domain     = domain,
                        subject    = domain,
                        issuer     = "Unknown (default)",
                        algorithm  = final_algo,
                        key_size   = final_key_size,
                        hndl_score = asset_hndl,
                        expires_at = None,
                        is_pqc     = is_pqc_ready(final_algo),
                    ))

                # 4e: Save Cipher Suites ───────────────────────────
                for suite_data in scan_data.get("cipher_suites", []):
                    kex  = suite_data.get("key_exchange", "RSA")
                    tver = suite_data.get("tls_version", "TLS 1.2")
                    # Use algorithm-specific vulnerability score for cipher suites (not 5-factor HNDL)
                    qr   = get_algorithm_vulnerability_score(kex)

                    db.add(CipherSuite(
                        suite_id              = str(uuid.uuid4()),
                        asset_id              = asset.asset_id,
                        name                  = suite_data.get("name", ""),
                        tls_version           = tver,
                        key_exchange          = kex,
                        quantum_risk          = qr,
                        is_quantum_vulnerable = is_quantum_vulnerable(kex),
                        strength              = (
                            "weak"   if qr > 6.0 else
                            "medium" if qr > 3.0 else
                            "strong"
                        ),
                    ))

                    if tver in ("TLS 1.0", "TLS 1.1", "SSLv3", "SSLv2"):
                        _create_finding(
                            db, asset.asset_id, FindingType.OUTDATED_TLS,
                            "HIGH", 7.5, "CWE-326",
                            f"Outdated TLS Version: {tver}",
                            f"Service supports {tver} which is deprecated and insecure.",
                            tver,
                        )

                # 4f: Quantum-vulnerability finding ────────────────
                if is_quantum_vulnerable(final_algo):

                    # Human-readable description of how we obtained this algo
                    source_labels = {
                        "openssl_cli":                  "OpenSSL CLI — direct TLS certificate inspection (real)",
                        "python_ssl":                   "Python ssl module — TLS handshake (real)",
                        "tls_scan":                     "TLS scan — cipher-suite inference (real)",
                        "origin_bypass":                "CT SAN origin-IP bypass — WAF bypassed, real leaf cert (real)",
                        "origin_bypass_ct_san":         "CT SAN origin-IP bypass — WAF bypassed, real leaf cert (real)",
                        "origin_bypass_spf":            "SPF record IP bypass — WAF bypassed via mail-server IP (real)",
                        "origin_bypass_passive_dns":    "Passive DNS historical IP bypass — WAF bypassed (approx IP, real cert)",
                        "ct_logs_issuer_inferred":      "CT logs — issuer-name inference (approximate, not leaf cert)",
                        "default":                      "Conservative RSA-2048 assumption (no data available)",
                    }
                    source_desc = source_labels.get(algorithm_source, algorithm_source)

                    # Label approximate / default results clearly in the UI
                    algo_display = f"{final_algo}-{final_key_size}"
                    if algorithm_source == "default":
                        algo_display += " (default — no data)"
                    elif algorithm_source == "ct_logs_issuer_inferred":
                        algo_display += " (approx — issuer inferred)"

                    finding = _create_finding(
                        db, asset.asset_id,
                        FindingType.QUANTUM_VULNERABLE_ALGO,
                        "CRITICAL" if asset_hndl >= 7.5 else "HIGH",
                        asset_hndl, "CWE-327",
                        f"Quantum-Vulnerable Algorithm: {algo_display}",
                        (
                            f"{final_algo} ({final_key_size}-bit) is breakable by Shor's algorithm on a "
                            f"cryptographically relevant quantum computer. "
                            f"Algorithm source: {source_desc}."
                        ),
                        final_algo,
                    )

                    if finding:
                        playbook = get_remediation_playbook("QUANTUM_VULNERABLE_ALGO", final_algo)
                        db.add(Remediation(
                            playbook_id    = str(uuid.uuid4()),
                            finding_id     = finding.finding_id,
                            priority       = playbook.get("priority", 5),
                            steps          = playbook.get("steps", []),
                            pqc_alternative= playbook.get("pqc_alternative", ""),
                        ))
                        for v in map_finding_to_compliance(
                            final_algo,
                            tls_data.get("tls_version", "")
                        ):
                            db.add(ComplianceTag(
                                tag_id      = str(uuid.uuid4()),
                                finding_id  = finding.finding_id,
                                framework   = v["framework"],
                                control_ref = v["control_ref"],
                                status      = "NON_COMPLIANT",
                                description = v["description"],
                            ))

                db.commit()

                processed_assets.append({
                    "domain":           domain,
                    "asset_id":         asset.asset_id,
                    "hndl_score":       asset_hndl,
                    "algorithm":        final_algo,
                    "key_size":         final_key_size,
                    "algorithm_source": algorithm_source,
                    "protocol":         protocol,
                })
                logger.info(
                    f"✅ {domain}: HNDL={asset_hndl} {final_algo}-{final_key_size} "
                    f"[{algorithm_source}] proto={protocol}"
                )

            except Exception as e:
                logger.error(f"Error scanning {domain}: {e}", exc_info=True)
                db.rollback()
                continue

        # ── STEP 5: Generate CBOM ─────────────────────────────────
        # Refresh session once more for final packaging
        db.close()
        db = SessionLocal()
        scan_job = db.query(ScanJob).filter(ScanJob.scan_id == scan_id).first()

        self.update_state(state="PROGRESS", meta={"progress": 90, "step": "Generating CBOM"})
        if scan_job:
            _generate_scan_cbom(db, scan_job, processed_assets)

            scan_job.status      = ScanStatus.COMPLETED
            scan_job.completed_at= datetime.utcnow()
            scan_job.progress    = 100
            db.commit()

        self.update_state(state="SUCCESS", meta={"progress": 100, "step": "Complete"})

        # ── Summary logging ───────────────────────────────────────
        algo_dist   = {}
        source_dist = {}
        for a in processed_assets:
            k = f"{a['algorithm']}-{a['key_size']}"
            algo_dist[k]   = algo_dist.get(k, 0) + 1
            s = a["algorithm_source"]
            source_dist[s] = source_dist.get(s, 0) + 1

        logger.info(f"Scan {scan_id} DONE | {len(processed_assets)} assets")
        logger.info(f"  Algorithm distribution: {algo_dist}")
        logger.info(f"  Source distribution:    {source_dist}")

        return {
            "status":               "completed",
            "scan_id":              scan_id,
            "assets":               len(processed_assets),
            "algo_distribution":    algo_dist,
            "source_distribution":  source_dist,
        }

    except Exception as e:
        logger.error(f"Scan {scan_id} FAILED: {e}", exc_info=True)
        if scan_job:
            scan_job.status = ScanStatus.FAILED
            db.commit()
        if self.request.retries < self.max_retries:
            raise self.retry(exc=e, countdown=30)

    finally:
        db.close()


# ─────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────

def _create_finding(db, asset_id, ftype, severity, hndl, cwe, title, desc, algo=""):
    try:
        f = Finding(
            finding_id  = str(uuid.uuid4()),
            asset_id    = asset_id,
            type        = ftype,
            severity    = severity,
            hndl_score  = hndl,
            cwe_id      = cwe,
            title       = title,
            description = desc,
            quantum_risk= hndl,
            details     = {"algorithm": algo},
        )
        db.add(f)
        # We don't flush here so we don't accidentally poison the transaction if it fails
        return f
    except Exception as e:
        logger.error(f"_create_finding failed: {e}")
        return None


def _generate_scan_cbom(db, scan_job, processed_assets):
    try:
        assets = db.query(Asset).filter(Asset.scan_id == scan_job.scan_id).all()
        full_assets = []
        for asset in assets:
            certs    = db.query(Certificate).filter(Certificate.asset_id == asset.asset_id).all()
            suites   = db.query(CipherSuite).filter(CipherSuite.asset_id == asset.asset_id).all()
            findings = db.query(Finding).filter(Finding.asset_id == asset.asset_id).all()
            full_assets.append({
                "asset_id":       asset.asset_id,
                "domain":         asset.domain,
                "hndl_score":     asset.hndl_score,
                "is_pqc":         asset.is_pqc,
                "pqc_readiness":  asset.pqc_readiness.value if asset.pqc_readiness else "Vulnerable",
                "is_cdn":         asset.is_cdn,
                "is_waf":         getattr(asset, "is_waf", False),
                "open_ports":     asset.open_ports or [],
                "resolved_ips":   asset.resolved_ips or [],
                "protocol":       asset.protocol.value if asset.protocol else "UNKNOWN",
                "service_category": asset.service_category,
                "certificates": [
                    {
                        "cert_id":    c.cert_id,
                        "subject":    c.subject,
                        "issuer":     c.issuer,
                        "algorithm":  c.algorithm,
                        "key_size":   c.key_size,
                        "hndl_score": c.hndl_score,
                        "expires_at": c.expires_at.isoformat() if c.expires_at else None,
                        "is_pqc":     c.is_pqc,
                    }
                    for c in certs
                ],
                "cipher_suites": [
                    {
                        "name":                 s.name,
                        "tls_version":          s.tls_version,
                        "key_exchange":         s.key_exchange,
                        "quantum_risk":         s.quantum_risk,
                        "is_quantum_vulnerable":s.is_quantum_vulnerable,
                    }
                    for s in suites
                ],
                "findings": [
                    {
                        "finding_id":  f.finding_id,
                        "type":        f.type.value if hasattr(f.type, "value") else f.type,
                        "severity":    f.severity,
                        "hndl_score":  f.hndl_score,
                        "cwe_id":      f.cwe_id,
                        "title":       f.title,
                        "description": f.description,
                        "remediation": f.remediation,
                        "quantum_risk":f.quantum_risk,
                    }
                    for f in findings
                ],
            })

        cbom_data = generate_cbom(
            {"scan_id": scan_job.scan_id, "org_name": scan_job.org_name},
            full_assets
        )
        db.add(CBOM(
            cbom_id  = str(uuid.uuid4()),
            scan_id  = scan_job.scan_id,
            format   = "CycloneDX",
            content  = cbom_data,
        ))
        db.commit()

    except Exception as e:
        logger.error(f"CBOM generation failed: {e}", exc_info=True)


def _get_data_sensitivity(domain: str) -> float:
    """
    Return a sensitivity weight (0–10) based on keywords in the domain name.
    Higher = more critical data → higher HNDL contribution.
    """
    d = domain.lower()
    if any(x in d for x in ["netbanking", "payment", "pay", "transaction"]):  return 10.0
    if any(x in d for x in ["swift", "cbdc", "rtgs", "neft"]):                return 9.5
    if any(x in d for x in ["vpn", "remote", "secure", "login", "auth", "iam"]): return 9.0
    if any(x in d for x in ["creditcard", "credit", "loan", "debit"]):        return 8.5
    if any(x in d for x in ["api", "apim", "gateway", "bbps", "upi", "graphql", "rest"]): return 7.5
    if any(x in d for x in ["mail", "smtp", "imap"]):                         return 6.0
    if any(x in d for x in ["cdn", "static", "assets", "img", "images"]):     return 2.0
    if any(x in d for x in ["www", "web"]):                                   return 5.0
    return 5.0


def _map_protocol(p: str) -> ProtocolType:
    return {
        "HTTPS": ProtocolType.HTTPS,
        "HTTP":  ProtocolType.HTTP,
        "SMTP":  ProtocolType.SMTP,
        "IMAP":  ProtocolType.IMAP,
        "POP3":  ProtocolType.POP3,
        "FTPS":  ProtocolType.FTPS,
        "SSH":   ProtocolType.SSH,
        "VPN":   ProtocolType.VPN,
    }.get(p.upper(), ProtocolType.UNKNOWN)


def _get_service_category(p: str, domain: str = "", server: str = None) -> str:
    """
    Categorize the service based on protocol, domain name, and server software.
    Identifies Web Servers, API Gateways, Load Balancers, etc.
    """
    p_upper = p.upper()
    d_lower = domain.lower()
    s_lower = (server or "").lower()

    # 1. API Gateways
    if any(x in d_lower for x in ["api", "apim", "gateway", "graphql"]):
        return "api_gateway"
    if any(x in s_lower for x in ["kong", "tyk", "apigee", "aws-api-gateway"]):
        return "api_gateway"

    # 2. Load Balancers / CDNs
    if any(x in s_lower for x in ["cloudflare", "akamai", "cloudfront", "f5", "citrix"]):
        return "load_balancer"

    # 3. Web Servers
    if p_upper in ["HTTPS", "HTTP"]:
        return "web_server"

    # 4. Others
    mapping = {
        "SMTP":  "mail_server",
        "IMAP":  "mail_server",
        "POP3":  "mail_server",
        "FTPS":  "file_transfer",
        "SSH":   "remote_access",
        "VPN":   "vpn_gateway",
    }
    return mapping.get(p_upper, "other_service")


def _map_pqc_readiness(label: str) -> PQCReadiness:
    return {
        "Quantum Safe":    PQCReadiness.QUANTUM_SAFE,
        "Partially Safe":  PQCReadiness.PARTIALLY_SAFE,
        "Vulnerable":      PQCReadiness.VULNERABLE,
        "Critical Risk":   PQCReadiness.CRITICAL,
    }.get(label, PQCReadiness.VULNERABLE)


# ─────────────────────────────────────────────────────────────────
# SCHEDULED RESCAN STUB
# ─────────────────────────────────────────────────────────────────

@shared_task(name="app.tasks.scan_tasks.run_scheduled_rescans")
def run_scheduled_rescans():
    logger.info("Running scheduled rescans...")
    pass