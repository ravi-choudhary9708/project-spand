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
import json
import redis
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse
from celery import shared_task
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.config import settings
from app.models.models import (
    ScanJob, Asset, Certificate, CipherSuite, Finding,
    Remediation, CBOM, ComplianceTag,
    ScanStatus, ProtocolType, FindingType, PQCReadiness
)
from app.scanning.scanner import scan_asset, run_subfinder, scan_via_origin_bypass
from app.scanning.ct_log_scanner import (
    get_domains_from_ct_logs, parse_ct_log_file, find_origin_targets_from_ct,
    get_historical_ips_viewdns, get_ips_from_spf, _is_known_cdn_ip,
    _looks_like_origin_host, _can_resolve, _IPv4_RE
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
    Handles known 2-part suffixes like co.in, bank.in, etc.
    """
    parts = domain.split(".")
    KNOWN_SUFFIXES = {
        "co.in", "ac.in", "gov.in", "org.in", "ernet.in", "res.in", "nic.in",
        "bank.in", "co.uk", "org.uk", "ac.uk", "gov.uk",
        "com.au", "net.au", "org.au", "edu.au", "gov.au"
    }
    if len(parts) > 2:
        suffix = f"{parts[-2]}.{parts[-1]}"
        if suffix in KNOWN_SUFFIXES:
            return ".".join(parts[-3:])
        else:
            return ".".join(parts[-2:])
    return domain


# ─────────────────────────────────────────────────────────────────
# CT LOG CACHE — built ONCE, shared across all domains in a scan
# ─────────────────────────────────────────────────────────────────

def _build_ct_cache(root_domain: str) -> dict:
    """
    Query crt.sh ONCE for a root domain.
    Returns {subdomain_lower: {algorithm, key_size, expires_at, issuer, source}}.

    Strategy:
      1. Check Redis cache first (TTL-based caching to avoid redundant API calls).
      2. If miss, try local crt.txt file (offline prepopulated cache).
      3. If miss, fall back to live crt.sh API.
      4. Store the result in Redis with 24h TTL.
    """
    redis_client = None
    cache_key = f"ct_cache:{root_domain}"
    try:
        redis_client = redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)
        cached_data = redis_client.get(cache_key)
        if cached_data:
            logger.info(f"CT cache (Redis hit): loaded cache for {root_domain}")
            
            def _deserialize_dates(d: dict) -> dict:
                for v in d.values():
                    for k in ["expires_at", "not_before"]:
                        if v.get(k):
                            try:
                                v[k] = datetime.fromisoformat(v[k])
                            except ValueError:
                                pass
                return d
            
            return _deserialize_dates(json.loads(cached_data))
    except Exception as e:
        logger.warning(f"Redis cache access failed for CT logs: {e}")

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

    # ── Fall back to live crt.sh API ─────────────────────────────
    if not cache:
        logger.info(f"CT cache: querying crt.sh API for {root_domain}")
        entries = get_domains_from_ct_logs(root_domain)
        for e in entries:
            d = e.get("domain", "").lower()
            if d:
                cache[d] = e
        logger.info(f"CT cache (API): {len(cache)} entries for {root_domain}")

    # Save to Redis
    if redis_client and cache:
        try:
            class DateTimeEncoder(json.JSONEncoder):
                def default(self, obj):
                    if isinstance(obj, datetime):
                        return obj.isoformat()
                    return super().default(obj)
            
            ttl_seconds = getattr(settings, "CT_CACHE_TTL_HOURS", 24) * 3600
            redis_client.setex(cache_key, ttl_seconds, json.dumps(cache, cls=DateTimeEncoder))
            logger.info(f"CT cache: Saved to Redis with TTL {ttl_seconds}s for {root_domain}")
        except Exception as e:
            logger.warning(f"Failed to save CT logs to Redis: {e}")

    return cache


# ─────────────────────────────────────────────────────────────────
# PARALLEL SCAN WORKERS
# ─────────────────────────────────────────────────────────────────

def _gather_target_profile(domain: str, root_domain: str, ct_cache_map: dict, root_info_map: dict) -> dict:
    """
    Fast concurrent gathering of 'passive' information for a single domain.
    Used pre-buffered root information for ViewDNS and SPF to avoid redundancy.
    """
    logger.info(f"[profile] Gathering data for {domain}")
    
    # 1. CT Log metadata (already buffered in ct_cache_map for the root)
    ct_entry = ct_cache_map.get(domain.lower(), {})
    
    # 2. Origin Bypass Candidates
    # Extract bypass targets FROM THE CACHE and pre-flight root info, not from a new API call
    origin_targets = list(root_info_map.get(root_domain, {}).get("origin_targets", []))

    return {
        "domain":         domain,
        "root_domain":    root_domain,
        "ct_entry":       ct_entry,
        "origin_targets": origin_targets,
    }


def _scan_single_domain(domain: str, scan_id: str, profile: dict) -> Optional[dict]:
    """
    Isolated worker function for parallel analysis of one domain.
    Handles Path A/B/C logic and persistence.
    """
    db = SessionLocal()
    try:
        logger.info(f"[worker] Starting analysis for {domain}")
        
        # ── 1. Heavy Analysis: Network scan ─────────────────────────
        # (nmap + TLS via openssl / python ssl)
        scan_data    = scan_asset(domain)
        protocol     = scan_data.get("protocol", "UNKNOWN")
        tls_data     = scan_data.get("tls_data", {})
        open_ports   = scan_data.get("open_ports", [])
        resolved_ips = scan_data.get("resolved_ips", [])
        is_cdn       = scan_data.get("is_cdn", False)

        # ── 2. Three-path algorithm decision ────────────────────────
        main_algorithm   = None
        main_key_size    = None
        expires_at       = None
        algorithm_source = "default"
        algorithm_confidence = "verified"

        # PATH A — verify TLS scan results
        for cert_data in scan_data.get("certificates", []):
            c_algo = cert_data.get("algorithm")
            if c_algo and main_algorithm is None:
                main_algorithm = c_algo
                main_key_size  = cert_data.get("key_size")
                algorithm_source = tls_data.get("algorithm_source") or tls_data.get("scan_method", "tls_scan")
                # Parse expiry
                not_after_str = cert_data.get("notAfter", "")
                if not_after_str:
                    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y", "%Y-%m-%d %H:%M:%S"):
                        try:
                            expires_at = datetime.strptime(not_after_str.strip(), fmt)
                            break
                        except: continue

        # PATH B1 — Origin Bypass (using pre-gathered profile)
        if not main_algorithm:
            origin_targets = profile.get("origin_targets", [])
            _B1_MAX_TARGETS = 3
            if origin_targets:
                logger.info(f"[worker] {domain}: Path B1 triggered. Found {len(origin_targets)} bypass candidates.")
            
            for target in origin_targets[:_B1_MAX_TARGETS]:
                t_value = target.get("value")
                if not t_value: continue
                
                logger.info(f"[worker] {domain}: Attempting Path B1 bypass via {t_value} ({target.get('source', 'unknown')})")
                
                # Fix: Use nmap-discovered ports for bypass, but skip port 80 (plain HTTP)
                bypass_ports = [p["port"] for p in open_ports if p["port"] != 80]
                bypass_data = scan_via_origin_bypass(domain, t_value, ports=bypass_ports if bypass_ports else None)
                bypass_certs = bypass_data.get("certificates", [])
                if bypass_certs:
                    c = bypass_certs[0]
                    main_algorithm = c.get("algorithm")
                    main_key_size  = c.get("key_size") or 2048
                    algorithm_source = f"origin_bypass_{target.get('source', 'ct_san')}"
                    
                    not_after_str = c.get("notAfter", "")
                    if not_after_str:
                        for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y"):
                            try:
                                expires_at = datetime.strptime(not_after_str.strip(), fmt)
                                break
                            except: continue
                    
                    scan_data["certificates"] = bypass_certs
                    scan_data["cipher_suites"] = bypass_data.get("cipher_suites", [])
                    logger.info(f"[worker] {domain}: PATH B1 SUCCESS via {t_value}")
                    break

        # PATH B2 — CT Fallback (using pre-gathered profile)
        if not main_algorithm:
            ct_entry = profile.get("ct_entry", {})
            if ct_entry:
                main_algorithm   = ct_entry.get("algorithm", "RSA")
                main_key_size    = ct_entry.get("key_size", 2048)
                expires_at       = ct_entry.get("expires_at")
                algorithm_source = "ct_logs_issuer_inferred"
                algorithm_confidence = "approximate"
                logger.info(f"[worker] {domain}: PATH B2 (CT Fallback)")
            else:
                # PATH C — Default
                main_algorithm   = "RSA"
                main_key_size    = 2048
                algorithm_source = "default"
                algorithm_confidence = "default"
                logger.info(f"[worker] {domain}: PATH C (Default)")

        # ── 3. Finalization: Scoring and Persistence ────────────────
        final_algo     = main_algorithm or "RSA"
        final_key_size = main_key_size  or 2048
        sensitivity    = _get_data_sensitivity(domain)
        
        # Protocol deduction
        if protocol == "UNKNOWN" and scan_data.get("cipher_suites"):
            _p = scan_data["cipher_suites"][0].get("port")
            _protocol_map = {443: "HTTPS", 8443: "HTTPS", 8080: "HTTPS", 465: "SMTP", 
                             587: "SMTP", 25: "SMTP", 993: "IMAP", 143: "IMAP", 
                             995: "POP3", 110: "POP3", 21: "FTPS", 990: "FTPS"}
            protocol = _protocol_map.get(_p, "UNKNOWN")

        # Scoring
        tls_version_str = tls_data.get("tls_version")
        asset_hndl_result = calculate_hndl_score(final_algo, final_key_size, sensitivity, expires_at, tls_version_str)
        asset_hndl = asset_hndl_result[0] if isinstance(asset_hndl_result, tuple) else asset_hndl_result
        hndl_breakdown = asset_hndl_result[1] if isinstance(asset_hndl_result, tuple) else {}
        pqc_label  = get_pqc_readiness_label(asset_hndl)

        # Save Asset
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
            scan_method=algorithm_source,
            algorithm_confidence=algorithm_confidence,
        )
        db.add(asset)
        db.flush()

        # Save Certificate(s)
        if scan_data.get("certificates"):
            for cert_data in scan_data["certificates"]:
                subj = cert_data.get("subject", {})
                iss  = cert_data.get("issuer", {})
                db.add(Certificate(
                    cert_id    = str(uuid.uuid4()),
                    asset_id   = asset.asset_id,
                    domain     = domain,
                    subject    = (subj.get("commonName", domain) if isinstance(subj, dict) else str(subj) or domain),
                    issuer     = (iss.get("organizationName") or iss.get("commonName") or "Unknown" if isinstance(iss, dict) else str(iss) or "Unknown"),
                    algorithm  = final_algo,
                    key_size   = final_key_size,
                    hndl_score = asset_hndl,
                    expires_at = expires_at,
                    is_pqc     = is_pqc_ready(final_algo),
                    is_approximate = False,
                ))
        elif profile.get("ct_entry"):
            # Synthetic cert from CT logs
            ct_entry = profile["ct_entry"]
            db.add(Certificate(
                cert_id    = str(uuid.uuid4()),
                asset_id   = asset.asset_id,
                domain     = domain,
                subject    = domain,
                issuer     = ct_entry.get("issuer", "Unknown"),
                algorithm  = final_algo,
                key_size   = final_key_size,
                hndl_score = asset_hndl,
                expires_at = expires_at,
                is_pqc     = is_pqc_ready(final_algo),
                is_approximate = True,
            ))
        else:
            # Default minimum
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
                is_approximate = True,
            ))

        # Save Cipher Suites
        for suite_data in scan_data.get("cipher_suites", []):
            kex  = suite_data.get("key_exchange", "RSA")
            tver = suite_data.get("tls_version", "TLS 1.2")
            qr   = get_algorithm_vulnerability_score(kex)
            db.add(CipherSuite(
                suite_id              = str(uuid.uuid4()),
                asset_id              = asset.asset_id,
                name                  = suite_data.get("name", ""),
                tls_version           = tver,
                key_exchange          = kex,
                quantum_risk          = qr,
                is_quantum_vulnerable = is_quantum_vulnerable(kex),
                strength              = ("weak" if qr > 6.0 else "medium" if qr > 3.0 else "strong"),
            ))
            if tver in ("TLS 1.0", "TLS 1.1", "SSL 3.0", "SSL 2.0", "SSLv3", "SSLv2"):
                _create_finding(db, asset.asset_id, FindingType.OUTDATED_TLS, "HIGH", 7.5, "CWE-326", f"Outdated Protocol: {tver}", f"Service supports {tver} which is deprecated.", tver)

        # Vulnerability findings (e.g. from testssl)
        testssl_vulns = tls_data.get("vulnerabilities", [])
        for vuln in testssl_vulns:
            v_type = FindingType.OUTDATED_TLS if vuln.get("type") == "OUTDATED_TLS" else FindingType.OTHER
            f = _create_finding(db, asset.asset_id, v_type, vuln.get("severity", "MEDIUM"), asset_hndl, vuln.get("cwe", "CWE-310"), vuln.get("title", "Vuln"), vuln.get("description", ""), final_algo)
            if f:
                for v in map_finding_to_compliance(final_algo, tls_data.get("tls_version", "")):
                    db.add(ComplianceTag(tag_id=str(uuid.uuid4()), finding_id=f.finding_id, framework=v["framework"], control_ref=v["control_ref"], status="NON_COMPLIANT", description=v["description"]))

        # Quantum Risk Finding
        if is_quantum_vulnerable(final_algo):
            finding = _create_finding(db, asset.asset_id, FindingType.QUANTUM_VULNERABLE_ALGO, "CRITICAL" if asset_hndl >= 7.5 else "HIGH", asset_hndl, "CWE-327", f"Quantum-Vulnerable Algorithm: {final_algo}", f"{final_algo} is breakable by Shor's algorithm.", final_algo)
            if finding:
                playbook = get_remediation_playbook("QUANTUM_VULNERABLE_ALGO", final_algo)
                db.add(Remediation(playbook_id=str(uuid.uuid4()), finding_id=finding.finding_id, priority=playbook.get("priority", 5), steps=playbook.get("steps", []), pqc_alternative=playbook.get("pqc_alternative", "")))
                for v in map_finding_to_compliance(final_algo, tls_data.get("tls_version", "")):
                    db.add(ComplianceTag(tag_id=str(uuid.uuid4()), finding_id=finding.finding_id, framework=v["framework"], control_ref=v["control_ref"], status="NON_COMPLIANT", description=v["description"]))

        db.commit()
        logger.info(f"[worker] Finished analysis for {domain}")
        return {
            "domain":           domain,
            "asset_id":         asset.asset_id,
            "hndl_score":       asset_hndl,
            "algorithm":        final_algo,
            "key_size":         final_key_size,
            "algorithm_source": algorithm_source,
            "protocol":         protocol,
        }
    except Exception as e:
        logger.error(f"[worker] Analysis failed for {domain}: {e}", exc_info=True)
        db.rollback()
        return None
    finally:
        db.close()


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

        # ── STEP 3: Root-Level Info Gathering (Parallel) ──────────
        ct_cache_map: dict = {}
        root_info_map: dict = {}
        seen_roots: set = set()
        for d in all_domains:
            seen_roots.add(_get_root_domain(d))
            
        self.update_state(state="PROGRESS", meta={"progress": 10, "step": f"Gathering root domain intelligence for {len(seen_roots)} root(s)"})
        
        def _get_root_intel(root):
            # 3a. CT Log metadata
            ct_cache = _build_ct_cache(root)
            intel = {"ct": ct_cache, "origin_targets": []}
            
            # 3b. Mine CT Cache for origin candidates once per root
            for val, entry in ct_cache.items():
                if _IPv4_RE.match(val):
                    intel["origin_targets"].append({"type": "ip", "value": val, "cert_domain": root, "source": "ct_cache"})
                elif _looks_like_origin_host(val):
                    # Only add if it's not the root itself (too generic)
                    if val != root:
                        intel["origin_targets"].append({
                            "type": "host", 
                            "value": val, 
                            "cert_domain": root, 
                            "resolvable": str(_can_resolve(val)), 
                            "source": "ct_cache"
                        })

            # 3c. SPF Mining (Root level)
            spf_ips = get_ips_from_spf(root)
            for ip in spf_ips:
                intel["origin_targets"].append({"type": "ip", "value": ip, "cert_domain": root, "source": "spf"})
            
            # 3d. Historical IPs (ViewDNS)
            hist_ips = get_historical_ips_viewdns(root)
            for ip in hist_ips:
                if not _is_known_cdn_ip(ip):
                    intel["origin_targets"].append({"type": "ip", "value": ip, "cert_domain": root, "source": "passive_dns"})
            
            return root, intel

        with ThreadPoolExecutor(max_workers=5) as root_executor:
            root_futures = [root_executor.submit(_get_root_intel, r) for r in seen_roots]
            for f in as_completed(root_futures):
                try:
                    # Apply a 60-second global timeout for any single root intel gathering
                    r, intel = f.result(timeout=60)
                    ct_cache_map.update(intel["ct"])
                    root_info_map[r] = {"origin_targets": intel["origin_targets"]}
                except Exception as e:
                    logger.warning(f"Root intel gathering timed out or failed for one or more roots: {e}")

        # ── STEP 4: Parallel Subdomain Profiling ──────────────────
        self.update_state(state="PROGRESS", meta={"progress": 15, "step": "Expanding target profiles (Parallel)"})
        target_profiles = {}
        with ThreadPoolExecutor(max_workers=15) as gather_executor:
            gather_futures = {
                gather_executor.submit(_gather_target_profile, domain, _get_root_domain(domain), ct_cache_map, root_info_map): domain
                for domain in all_domains
            }
            for future in as_completed(gather_futures):
                domain = gather_futures[future]
                try:
                    target_profiles[domain] = future.result()
                except Exception as e:
                    logger.warning(f"Profiling failed for {domain}: {e}")
                    target_profiles[domain] = {
                        "domain": domain, "root_domain": _get_root_domain(domain),
                        "ct_entry": ct_cache_map.get(domain.lower(), {}), "origin_targets": []
                    }

        # ── STEP 5: Parallel Analysis (Heavy Scan Stage) ─────────
        MAX_PARALLEL_DOMAINS = 5  # Moderate to avoid network saturation
        total = len(all_domains)
        processed_assets = []
        completed_count = 0
        
        self.update_state(state="PROGRESS", meta={"progress": 20, "step": f"Starting parallel scan (workers={MAX_PARALLEL_DOMAINS})"})
        
        with ThreadPoolExecutor(max_workers=MAX_PARALLEL_DOMAINS) as scan_executor:
            scan_futures = {
                scan_executor.submit(_scan_single_domain, domain, scan_id, target_profiles.get(domain, {})): domain
                for domain in all_domains
            }
            
            for future in as_completed(scan_futures):
                domain = scan_futures[future]
                completed_count += 1
                try:
                    result = future.result()
                    if result:
                        processed_assets.append(result)
                except Exception as e:
                    logger.error(f"Worker crashed for {domain}: {e}")
                
                # Update progress
                progress = int(20 + (completed_count / max(total, 1)) * 68)
                self.update_state(state="PROGRESS", meta={
                    "progress": progress,
                    "step":     f"Parallel Scan: {completed_count}/{total} domains complete"
                })
                
                # Periodically update scan_job progress in DB
                if completed_count % 5 == 0 or completed_count == total:
                    db.close()
                    db = SessionLocal()
                    job = db.query(ScanJob).filter(ScanJob.scan_id == scan_id).first()
                    if job:
                        job.progress = progress
                        db.commit()

        # ── STEP 6: Generate CBOM ─────────────────────────────────
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