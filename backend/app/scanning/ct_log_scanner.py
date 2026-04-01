"""
CT Log Scanner — Certificate Transparency Integration
=====================================================

Two purposes:
  1. Build a domain→metadata cache (algorithm, expiry, issuer) from crt.sh
  2. Find "origin" IPs / internal hostnames hidden in cert SANs for WAF bypass

─── WHY ISSUER INFERENCE IS WRONG ────────────────────────────────────────────
  The issuer name (e.g. "GlobalSign GCC R3 EV TLS CA 2025") tells us the CA's
  algorithm — NOT the leaf certificate's actual key algorithm.
  A GlobalSign RSA CA can sign *either* RSA *or* ECDSA leaf certs.
  We must get the leaf cert to know the real algorithm.

─── THE RIGHT WAY: ORIGIN IP BYPASS ──────────────────────────────────────────
  crt.sh lists every SAN (Subject Alternative Name) in each certificate.
  A cert for "rekyc.pnb.bank.in" may ALSO cover:
    • An internal host:  origin-rekyc.pnb.bank.in  → connect directly (no WAF)
    • An IP SAN:         103.109.104.26              → connect to IP, SNI = domain

  By TCP-connecting to that origin IP/host and sending the original domain
  as TLS SNI, the server presents its real leaf certificate — revealing the
  ACTUAL algorithm (RSA-2048, ECDSA-256 …), not a CA-level guess.

─── PIPELINE (called from scan_tasks.py) ─────────────────────────────────────
  PATH A  : nmap open → TLS direct → openssl → real algo       ✓
  PATH B1 : nmap blocked → CT SANs → origin IP → TLS+SNI → real algo ✓✓
  PATH B2 : no origin IP found → CT expiry date stored (algo inferred ~approx)
  PATH C  : nothing → RSA-2048 conservative default

─── PUBLIC FUNCTIONS ─────────────────────────────────────────────────────────
  get_domains_from_ct_logs(domain)     → live crt.sh API query
  parse_ct_log_file(filepath)          → parse local crt.txt export
  find_origin_targets_from_ct(domain)  → mine SANs for bypass IPs/hosts
"""

import re
import logging
import socket
import ipaddress
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple

logger = logging.getLogger(__name__)

# ── Heuristic patterns that suggest a SAN is an internal/origin host ──────────
_ORIGIN_PATTERNS = [
    "origin",     # origin-api.example.com  or  api-origin.example.com
    "real",       # real-site.example.com
    "backend",    # backend.example.com
    "direct",     # direct.example.com
    "internal",   # internal.example.com
    "src",        # src.example.com
    "-dc.",       # data-centre
    "-dr.",       # disaster-recovery
    "edge",       # edge-node that is NOT Akamai/Cloudflare
]

_IPv4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

# ── Known CDN IP ranges (CIDR) for filtering out edge-node IPs ────────────────
_CDN_CIDRS = [
    # Cloudflare
    "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "104.16.0.0/13", "104.24.0.0/14",
    "108.162.192.0/18", "131.0.72.0/22",
    "141.101.64.0/18", "162.158.0.0/15",
    "172.64.0.0/13", "173.245.48.0/20",
    "188.114.96.0/20", "190.93.240.0/20",
    "197.234.240.0/22", "198.41.128.0/17",
    # Akamai (selected ranges)
    "23.32.0.0/11", "104.64.0.0/10",
    # Fastly
    "151.101.0.0/16",
    # CloudFront (selected)
    "54.230.0.0/16", "54.240.128.0/18",
]
_CDN_NETWORKS = [ipaddress.ip_network(c) for c in _CDN_CIDRS]


# ─────────────────────────────────────────────────────────────────────────────
# 1.  LIVE crt.sh API
# ─────────────────────────────────────────────────────────────────────────────

def get_domains_from_ct_logs(domain: str) -> List[Dict[str, Any]]:
    """
    Query crt.sh CT logs for a root domain.
    Returns all subdomains with expiry + issuer metadata.

    NOTE: algorithm/key_size here is inferred from issuer CN — approximate.
    Use find_origin_targets_from_ct() + scan_via_origin_bypass() for real algo.
    """
    try:
        import requests
    except ImportError:
        logger.warning("requests not available — CT log API skipped")
        return []

    results: List[Dict[str, Any]] = []
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        logger.info(f"CT API: {url}")

        resp = requests.get(url, timeout=30, headers={
            "User-Agent": "QuantumShield-Scanner/1.0 (Security Research)"
        })

        if resp.status_code != 200:
            logger.warning(f"crt.sh HTTP {resp.status_code} for {domain}")
            return []

        entries = resp.json()
        logger.info(f"crt.sh: {len(entries)} raw certificates for {domain}")

        domain_map: Dict[str, Dict] = {}

        for entry in entries:
            name_value  = entry.get("name_value", "")
            common_name = entry.get("common_name", "")
            issuer_name = entry.get("issuer_name", "")
            not_after   = entry.get("not_after", "")
            not_before  = entry.get("not_before", "")
            logged_at   = entry.get("entry_timestamp", "")

            algorithm, key_size = _infer_algo_from_issuer(issuer_name)
            expires_at = _parse_date(not_after)

            all_names: set = set()
            all_names.add(common_name.strip())
            for n in name_value.split("\n"):
                n = n.strip()
                if n and "." in n and not n.startswith("*"):
                    all_names.add(n)

            for sub in all_names:
                sub = sub.strip().lower()
                if not sub or not sub.endswith(domain):
                    continue
                if sub.startswith("*."):
                    continue

                existing = domain_map.get(sub)
                if existing is None or (logged_at and logged_at > existing.get("logged_at", "")):
                    domain_map[sub] = {
                        "domain":     sub,
                        "algorithm":  algorithm,
                        "key_size":   key_size,
                        "issuer":     _clean_issuer(issuer_name),
                        "expires_at": expires_at,
                        "not_before": _parse_date(not_before),
                        "logged_at":  logged_at,
                        "source":     "ct_logs_api",
                    }

        results = list(domain_map.values())
        logger.info(f"CT API: {len(results)} unique domains for {domain}")

    except Exception as e:
        logger.error(f"CT API failed for {domain}: {e}", exc_info=True)

    return results


# ─────────────────────────────────────────────────────────────────────────────
# 2.  LOCAL crt.txt FILE PARSER
# ─────────────────────────────────────────────────────────────────────────────

def parse_ct_log_file(filepath: str) -> List[Dict[str, Any]]:
    """
    Parse a local crt.sh TSV export (e.g. crt.txt).

    Format (tab-separated):
      crt_id \\t logged_at \\t not_before \\t not_after \\t CN \\t matching_identities \\t issuer

    Handles multi-line matching_identities (SANs on continuation lines).
    """
    domain_map: Dict[str, Dict] = {}

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.read().replace("\r\n", "\n").replace("\r", "\n").split("\n")

        logger.info(f"CT file: {len(lines)} lines from {filepath}")

        current_issuer    = ""
        current_not_after = ""
        pending_names: List[str] = []

        def _flush():
            if not pending_names:
                return
            algorithm, key_size = _infer_algo_from_issuer(current_issuer)
            expires_at = _parse_date_ymd(current_not_after)
            for name in pending_names:
                name = name.strip().lower()
                if not name or "." not in name:
                    continue
                if name not in domain_map:
                    domain_map[name] = {
                        "domain":     name,
                        "algorithm":  algorithm,
                        "key_size":   key_size,
                        "issuer":     _clean_issuer(current_issuer),
                        "expires_at": expires_at,
                        "source":     "ct_logs_file",
                    }

        for line in lines:
            s = line.strip()
            if not s:
                continue
            if s.startswith("crt.sh ID") or s.startswith("Certificates"):
                continue

            parts = s.split("\t")

            if parts[0].strip().isdigit():
                _flush()
                pending_names = []
                current_not_after = parts[3].strip() if len(parts) > 3 else ""
                issuer_raw        = parts[6].strip() if len(parts) > 6 else ""
                matching_raw      = parts[5].strip() if len(parts) > 5 else ""
                current_issuer    = issuer_raw

                for sub in matching_raw.split("\n"):
                    sub = sub.strip().lower()
                    if sub and "." in sub and not sub.startswith("c="):
                        pending_names.append(sub)

            else:
                # Continuation lines / tab-separated trailing issuer
                if "\t" in s:
                    left, *rest = s.split("\t")
                    if left.strip() and "." in left:
                        pending_names.append(left.strip().lower())
                    tail = rest[-1].strip() if rest else ""
                    if "CN=" in tail:
                        current_issuer = tail
                elif (
                    "." in s
                    and "=" not in s
                    and not s.startswith("Not ")
                    and not s.startswith("Certificate")
                    and len(s.split(".")[-1]) <= 6
                ):
                    pending_names.append(s.lower())

        _flush()

        results = list(domain_map.values())
        logger.info(f"CT file parsed: {len(results)} unique domains from {filepath}")

    except Exception as e:
        logger.error(f"CT file parse failed for {filepath}: {e}", exc_info=True)
        results = []

    return results


# ─────────────────────────────────────────────────────────────────────────────
# 3.  ORIGIN TARGET FINDER  ← THE KEY IMPROVEMENT
# ─────────────────────────────────────────────────────────────────────────────

def find_origin_targets_from_ct(domain: str, ct_cache: dict = None) -> List[Dict[str, str]]:
    """
    Mine crt.sh SANs to find origin IPs / internal hostnames for WAF bypass.

    For each certificate that covers `domain`, inspect ALL SANs for:
      • Direct IPv4 addresses (IP SANs) — connect directly, SNI = domain
      • Internal/origin-looking hostnames — may resolve without CDN in the way

    If `ct_cache` is provided (from the scan pipeline), uses cached entries
    to avoid a redundant crt.sh API call.

    Returns list of:
      {
        "type":        "ip" | "host",
        "value":       "103.109.104.26" | "origin-rekyc.pnb.bank.in",
        "cert_domain": "rekyc.pnb.bank.in",   ← use as TLS SNI
        "resolvable":  True | False,           ← whether DNS resolved
      }
    """
    targets: List[Dict[str, str]] = []
    seen: set = set()

    # ── Fast path: extract origin hints from pre-built CT cache ───────
    if ct_cache:
        logger.info(f"CT origin-bypass: using pre-built cache ({len(ct_cache)} entries)")
        for cached_domain in ct_cache:
            cd = cached_domain.strip().lower()
            if not cd:
                continue
            # Check all cached domains for IP SANs or origin-looking hostnames
            if _IPv4_RE.match(cd):
                if cd not in seen:
                    seen.add(cd)
                    targets.append({
                        "type": "ip", "value": cd,
                        "cert_domain": domain, "resolvable": "True",
                    })
            elif cd != domain.lower() and not cd.startswith("*."):
                if _looks_like_origin_host(cd) and cd not in seen:
                    seen.add(cd)
                    resolvable = _can_resolve(cd)
                    targets.append({
                        "type": "host", "value": cd,
                        "cert_domain": domain, "resolvable": str(resolvable),
                    })
        if targets:
            logger.info(f"CT origin-bypass (cache): {len(targets)} bypass targets for {domain}")
            return targets
        # If cache had no origin hints, fall through to API

    # ── Slow path: live crt.sh API query ──────────────────────────────
    try:
        import requests
    except ImportError:
        logger.warning("requests not available — origin bypass skipped")
        return []

    try:
        root = _get_root_domain(domain)
        url = f"https://crt.sh/?q=%.{root}&output=json"
        logger.info(f"CT origin-bypass query (wildcard root): {url}")

        resp = requests.get(url, timeout=30, headers={
            "User-Agent": "QuantumShield-Scanner/1.0 (Security Research)"
        })

        if resp.status_code != 200:
            logger.warning(f"crt.sh HTTP {resp.status_code} for origin lookup of {domain}")
            return []

        entries = resp.json()
        logger.info(f"CT origin-bypass: {len(entries)} certs for {domain}")

        for entry in entries:
            name_value  = entry.get("name_value", "")
            common_name = entry.get("common_name", "")

            all_names: List[str] = []
            all_names.append(common_name.strip())
            for n in name_value.split("\n"):
                n = n.strip()
                if n:
                    all_names.append(n)

            for san in all_names:
                san = san.strip()
                if not san or san in seen:
                    continue

                if _IPv4_RE.match(san):
                    seen.add(san)
                    logger.info(f"CT origin-bypass: found IP SAN {san} for {domain}")
                    targets.append({
                        "type":        "ip",
                        "value":       san,
                        "cert_domain": domain,
                        "resolvable":  "True",
                    })
                    continue

                san_lower = san.lower()
                if san_lower == domain.lower():
                    continue
                if san_lower.startswith("*."):
                    continue

                if _looks_like_origin_host(san_lower):
                    seen.add(san_lower)
                    resolvable = _can_resolve(san_lower)
                    logger.info(
                        f"CT origin-bypass: internal host {san_lower} "
                        f"(resolvable={resolvable}) for {domain}"
                    )
                    targets.append({
                        "type":        "host",
                        "value":       san_lower,
                        "cert_domain": domain,
                        "resolvable":  str(resolvable),
                    })

    except Exception as e:
        logger.error(f"Origin target lookup failed for {domain}: {e}", exc_info=True)

    logger.info(f"CT origin-bypass: {len(targets)} bypass targets for {domain}")
    return targets


# ─────────────────────────────────────────────────────────────────────────────
# 4.  HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _looks_like_origin_host(hostname: str) -> bool:
    """Heuristic: does this SAN look like an internal/origin host?"""
    h = hostname.lower()
    for pattern in _ORIGIN_PATTERNS:
        if pattern in h:
            return True
    return False


def _can_resolve(hostname: str) -> bool:
    """Quick DNS check — does this hostname resolve?"""
    try:
        socket.gethostbyname(hostname)
        return True
    except Exception:
        return False


def _infer_algo_from_issuer(issuer: str) -> Tuple[str, int]:
    """
    APPROXIMATE: infer algorithm from issuer CN.

    ⚠️  This is a FALLBACK only — it tells us the CA's preferred algorithm,
        not necessarily what the leaf cert uses.
        Use find_origin_targets_from_ct() + TLS bypass for the real answer.

    Examples:
      "GlobalSign GCC R3 EV TLS CA 2025"       → RSA, 2048  (GCC R-series = RSA)
      "GeoTrust EV RSA CA G2"                   → RSA, 2048
      "DigiCert Verified Mark RSA4096 ..."      → RSA, 4096
      "DigiCert TLS ECC P-384 SHA384 2021 CA1"  → ECDSA, 384
      "GlobalSign ECC Root CA - R5"             → ECDSA, 256
      "Let's Encrypt E1"                        → ECDSA, 256
      "Let's Encrypt R3"                        → RSA,   2048
      "Thawte TLS RSA CA G1"                    → RSA,   2048
    """
    iu = issuer.upper()

    # ECC / ECDSA — check before RSA (some issuers have both words)
    if "ECC" in iu or "ECDSA" in iu or "EC TLS" in iu:
        if "P-384" in iu or "384" in iu:
            return "ECDSA", 384
        if "P-521" in iu or "521" in iu:
            return "ECDSA", 521
        return "ECDSA", 256

    # RSA with explicit size
    if "RSA4096" in iu or "RSA 4096" in iu:
        return "RSA", 4096
    if "RSA2048" in iu or "RSA 2048" in iu:
        return "RSA", 2048

    # RSA generic
    if "RSA" in iu:
        m = re.search(r"RSA[- ]?(\d{4})", iu)
        if m:
            return "RSA", int(m.group(1))
        return "RSA", 2048

    # Let's Encrypt E-series = ECDSA, R-series = RSA
    le = re.search(r"\b(E|R)\d+\b", iu)
    if le and "ENCRYPT" in iu:
        return ("ECDSA", 256) if le.group(1) == "E" else ("RSA", 2048)

    # Well-known CAs default to RSA-2048
    if any(k in iu for k in ("GLOBALSIGN", "GEOTRUST", "DIGICERT", "THAWTE",
                               "SECTIGO", "COMODO", "ENTRUST", "GODADDY")):
        return "RSA", 2048

    return "RSA", 2048   # conservative default


def _clean_issuer(issuer_raw: str) -> str:
    """Extract CN= value from a full DN string."""
    for part in issuer_raw.split(","):
        part = part.strip()
        if part.upper().startswith("CN="):
            return part[3:].strip()
    return (issuer_raw[:80] if issuer_raw else "Unknown")


def _parse_date(date_str: str) -> Optional[datetime]:
    """Parse crt.sh API date: '2026-07-22T00:00:00' or '2026-07-22 00:00:00'."""
    if not date_str:
        return None
    s = str(date_str)
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(s[:19], fmt)
        except ValueError:
            continue
    return None


def _parse_date_ymd(date_str: str) -> Optional[datetime]:
    """Parse crt.sh file date: '2026-10-12'."""
    if not date_str:
        return None
    try:
        return datetime.strptime(str(date_str)[:10], "%Y-%m-%d")
    except ValueError:
        return None


def _get_root_domain(domain: str) -> str:
    """
    Derive the root domain for CT log wildcard queries.
      netbanking.pnb.bank.in → pnb.bank.in   (4-part → last 3)
      api.example.com        → example.com    (3-part → last 2)
    """
    parts = domain.split(".")
    if len(parts) >= 4:
        return ".".join(parts[-3:])
    if len(parts) >= 3:
        return ".".join(parts[-2:])
    return domain


# ─────────────────────────────────────────────────────────────────────────────
# 5.  CDN IP FILTER
# ─────────────────────────────────────────────────────────────────────────────

def _is_known_cdn_ip(ip: str) -> bool:
    """
    Returns True if `ip` falls within a known CDN address range.
    Used to filter out edge-node IPs from passive DNS / SPF results.
    """
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _CDN_NETWORKS)
    except ValueError:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# 6.  PASSIVE DNS — Historical IP Mining  (data: APPROX — IPs may be stale)
# ─────────────────────────────────────────────────────────────────────────────

def get_historical_ips_viewdns(domain: str) -> List[str]:
    """
    Query ViewDNS.info for historical A-record IPs.
    Returns IPs the domain pointed to before moving behind a CDN.

    Data quality: APPROXIMATE — historical IPs may no longer be active.
    """
    try:
        import requests
    except ImportError:
        logger.warning("requests not available — ViewDNS lookup skipped")
        return []

    try:
        url = f"https://api.viewdns.info/iphistory/?domain={domain}&apikey=free&output=json"
        resp = requests.get(url, timeout=15, headers={
            "User-Agent": "QuantumShield-Scanner/1.0 (Security Research)"
        })
        data = resp.json()
        ips: List[str] = []
        for record in data.get("response", {}).get("records", []):
            ip = record.get("ip", "")
            if ip and not _is_known_cdn_ip(ip):
                ips.append(ip)
        logger.info(f"ViewDNS historical IPs for {domain}: {ips}")
        return ips
    except Exception as e:
        logger.debug(f"ViewDNS lookup failed for {domain}: {e}")
        return []


# ─────────────────────────────────────────────────────────────────────────────
# 7.  SPF RECORD MINING  (data: REAL — current DNS TXT records)
# ─────────────────────────────────────────────────────────────────────────────

def get_ips_from_spf(domain: str, _depth: int = 0) -> List[str]:
    """
    Mine SPF TXT records for ip4: directives.
    SPF often reveals origin/mail-server IPs sharing the same /24 as the web origin.

    Data quality: REAL — these are live DNS records.
    Recursively follows `include:` directives (max depth 3).
    """
    if _depth > 3:
        return []  # prevent infinite recursion

    try:
        import dns.resolver
    except ImportError:
        logger.warning("dnspython not available — SPF lookup skipped")
        return []

    ips: List[str] = []
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        for rdata in answers:
            txt = b"".join(rdata.strings).decode("utf-8", errors="ignore")
            if "v=spf1" not in txt.lower():
                continue
            for part in txt.split():
                if part.startswith("ip4:"):
                    ip = part[4:].split("/")[0]  # strip CIDR mask
                    if not _is_known_cdn_ip(ip):
                        ips.append(ip)
                elif part.startswith("include:") and _depth < 3:
                    sub = part[8:]
                    ips.extend(get_ips_from_spf(sub, _depth + 1))
        logger.info(f"SPF ips for {domain}: {ips}")
    except Exception as e:
        logger.debug(f"SPF lookup failed for {domain}: {e}")
    return ips
