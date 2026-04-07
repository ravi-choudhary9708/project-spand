"""
Scanning Engine - Main orchestrator
Wraps Nmap, OpenSSL CLI, SSLyze, and Subfinder with a smart fallback to
Python ssl module for environments where tools are unavailable.


  - Real algorithm & key size extracted via `openssl s_client` + `openssl x509`
  - Real issuer name extracted from certificate
  - TLS scan runs on ALL TLS-capable ports (443, 8443, 465, 587, 993, 995, 990, etc.)
  - UNKNOWN protocol domains still attempt TLS scan on any open port
  - Cipher suite extracted via Python ssl interface (real negotiated cipher)
"""
import subprocess
import concurrent.futures
import time
import json
import os
import re
import socket
import ssl
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
import logging

logger = logging.getLogger(__name__)


# Ports that carry TLS (STARTTLS variants included via -starttls flag)
TLS_PORTS = {
    443:  {"proto": "HTTPS",  "starttls": None},
    8443: {"proto": "HTTPS",  "starttls": None},
    465:  {"proto": "SMTPS",  "starttls": None},
    587:  {"proto": "SMTP",   "starttls": "smtp"},
    25:   {"proto": "SMTP",   "starttls": "smtp"},
    993:  {"proto": "IMAPS",  "starttls": None},
    143:  {"proto": "IMAP",   "starttls": "imap"},
    995:  {"proto": "POP3S",  "starttls": None},
    110:  {"proto": "POP3",   "starttls": "pop3"},
    990:  {"proto": "FTPS",   "starttls": None},
    21:   {"proto": "FTP",    "starttls": "ftp"},
    22:   {"proto": "SSH",    "starttls": None},   # SSH uses its own key exchange
    1194: {"proto": "VPN",    "starttls": None},
    1723: {"proto": "VPN",    "starttls": None},
    500:  {"proto": "VPN",    "starttls": None},
}


def run_command(cmd: List[str], timeout: int = 60, input_data: str = None) -> Dict[str, Any]:
    """Run a shell command and return stdout/stderr."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_data,
        )
        return {"stdout": result.stdout, "stderr": result.stderr, "returncode": result.returncode}
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": "Timeout", "returncode": -1}
    except FileNotFoundError:
        return {"stdout": "", "stderr": f"Command not found: {cmd[0]}", "returncode": -2}
    except Exception as e:
        return {"stdout": "", "stderr": str(e), "returncode": -3}


def is_tool_available(tool: str) -> bool:
    """Check if a CLI tool is available in PATH."""
    result = run_command(["which", tool] if os.name != "nt" else ["where", tool], timeout=5)
    return result["returncode"] == 0


# ─────────────────────────────────────────
# SUBFINDER
# ─────────────────────────────────────────

def run_subfinder(domain: str) -> List[str]:
    """Discover subdomains using Subfinder."""
    if not is_tool_available("subfinder"):
        logger.warning("subfinder not found, using DNS fallback")
        return _subfinder_fallback(domain)

    result = run_command(["subfinder", "-d", domain, "-silent", "-timeout", "30"], timeout=60)

    if result["returncode"] == 0 and result["stdout"]:
        subdomains = [s.strip() for s in result["stdout"].split("\n") if s.strip()]
        return subdomains

    return [domain]


def _subfinder_fallback(domain: str) -> List[str]:
    """Fallback: try common DNS prefixes."""
    common = ["www", "mail", "api", "ftp", "smtp", "imap", "vpn", "secure", "app"]
    discovered = [domain]

    for prefix in common:
        sub = f"{prefix}.{domain}"
        try:
            socket.gethostbyname(sub)
            discovered.append(sub)
        except socket.gaierror:
            pass

    return discovered


# ─────────────────────────────────────────
# DNS
# ─────────────────────────────────────────

def resolve_dns(domain: str) -> List[str]:
    try:
        results = socket.getaddrinfo(domain, None)
        return list(set([r[4][0] for r in results]))
    except Exception:
        return []


# ─────────────────────────────────────────
# NMAP
# ─────────────────────────────────────────

def run_nmap_scan(target: str) -> Dict[str, Any]:

    if not is_tool_available("nmap"):
        logger.warning("nmap not found, using fallback scan")
        return _nmap_fallback(target)

    ports = "443,8443,25,587,465,143,993,110,995,21,990,22,1194,1723,500"

    # Fast SYN scan — service version detection and SSL scripts are NOT needed
    # because TLS/cert data is gathered separately via openssl/python ssl.
    result = run_command(
        ["nmap", "-sS", "-p", ports, "--open", "-T4", "--max-retries", "1", target],
        timeout=30
    )
    print("nmap result:", result)

    return _parse_nmap_output(result["stdout"], target)


def _nmap_fallback(target: str) -> Dict[str, Any]:

    ports = {
        443: "HTTPS", 8443: "HTTPS",
        25: "SMTP", 587: "SMTP", 465: "SMTPS",
        143: "IMAP", 993: "IMAPS",
        110: "POP3", 995: "POP3S",
        21: "FTP", 990: "FTPS",
        22: "SSH",
        1194: "VPN", 1723: "VPN", 500: "VPN",
    }

    def _check_port(port_service):
        port, service = port_service
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.5)
            result = sock.connect_ex((target, port))
            sock.close()
            if result == 0:
                return {"port": port, "service": service, "state": "open"}
        except Exception:
            pass
        return None

    # Check all ports concurrently — ~1.5s total instead of ~30s sequential
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
        results = executor.map(_check_port, ports.items())
        open_ports = [r for r in results if r is not None]
    print("open port:",open_ports)

    return {"target": target, "open_ports": open_ports, "raw": ""}


def _parse_nmap_output(output: str, target: str) -> Dict[str, Any]:

    open_ports = []

    for line in output.split("\n"):

        if "/tcp" in line and "open" in line:

            parts = line.split()

            if len(parts) >= 3:

                port = int(parts[0].split("/")[0])
                service = parts[2]

                open_ports.append({
                    "port": port,
                    "service": service,
                    "state": "open"
                })

    return {"target": target, "open_ports": open_ports, "raw": output[:2000]}


# ─────────────────────────────────────────
# OPENSSL CLI - Real Algorithm & Key Size
# ─────────────────────────────────────────

def _openssl_available() -> bool:
    return is_tool_available("openssl")


def _get_cert_pem_via_openssl(domain: str, port: int, starttls: Optional[str] = None) -> Optional[str]:
    """
    Use `openssl s_client` to retrieve the PEM certificate from a server.
    Supports STARTTLS for SMTP/IMAP/POP3/FTP.
    Returns the PEM string or None on failure.
    """
    cmd = ["openssl", "s_client", "-connect", f"{domain}:{port}", "-servername", domain, "-showcerts"]
    if starttls:
        cmd += ["-starttls", starttls]

    result = run_command(cmd, timeout=15, input_data="Q\n")

    if result["returncode"] not in (0, 1) or not result["stdout"]:
        # Try without SNI (IP targets, unknown protocol)
        cmd2 = ["openssl", "s_client", "-connect", f"{domain}:{port}", "-showcerts"]
        if starttls:
            cmd2 += ["-starttls", starttls]
        result = run_command(cmd2, timeout=15, input_data="Q\n")

    stdout = result["stdout"]
    print("openssl stdout:",stdout)
    # Extract first certificate PEM block
    match = re.search(r"(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)", stdout, re.DOTALL)
    if match:
        return match.group(1)
    return None


def _parse_openssl_x509(pem: str) -> Dict[str, Any]:
    """
    Parse a PEM certificate with `openssl x509` to extract:
      - algorithm (signature algorithm)
      - key_size  (public key bit length)
      - subject
      - issuer
      - notAfter
      - serialNumber
      - subjectAltName
    """
    info: Dict[str, Any] = {
        "algorithm": None,
        "key_size": None,
        "subject": {},
        "issuer": {},
        "notAfter": "",
        "serialNumber": "",
        "subjectAltName": [],
    }

    # Run openssl x509 -text -noout
    result = run_command(
        ["openssl", "x509", "-text", "-noout"],
        timeout=10,
        input_data=pem,
    )

    text = result["stdout"]
    if not text:
        return info

    # ── Signature Algorithm ──────────────────────
    # Appears as: Signature Algorithm: sha256WithRSAEncryption
    sig_match = re.search(r"Signature Algorithm:\s*(\S+)", text)
    if sig_match:
        raw_alg = sig_match.group(1)
        info["algorithm"] = _normalize_algorithm(raw_alg)

    # ── Public Key Algorithm + Size ──────────────
    # e.g.  "Public Key Algorithm: rsaEncryption"
    #        "RSA Public-Key: (2048 bit)"
    #        "Public-Key: (256 bit)"          <- EC key
    key_alg_match = re.search(r"Public Key Algorithm:\s*(\S+)", text)
    if key_alg_match:
        key_alg_raw = key_alg_match.group(1)
        # If signature algorithm was not found yet, derive from key algorithm
        if not info["algorithm"]:
            info["algorithm"] = _normalize_algorithm(key_alg_raw)

    key_size_match = re.search(r"(?:RSA Public-Key|Public-Key|EC):\s*\((\d+)\s*bit\)", text)
    if key_size_match:
        info["key_size"] = int(key_size_match.group(1))

    # Also handle EC curves where bit size can be inferred from curve name
    if info["key_size"] is None:
        curve_match = re.search(r"ASN1 OID:\s*(\S+)", text)
        if curve_match:
            curve = curve_match.group(1)
            info["key_size"] = _curve_to_bits(curve)

    # ── Subject ─────────────────────────────────
    subj_match = re.search(r"Subject:\s*(.+)", text)
    if subj_match:
        info["subject"] = _parse_dn(subj_match.group(1))

    # ── Issuer ──────────────────────────────────
    issuer_match = re.search(r"Issuer:\s*(.+)", text)
    if issuer_match:
        info["issuer"] = _parse_dn(issuer_match.group(1))

    # ── Validity / notAfter ──────────────────────
    not_after_match = re.search(r"Not After\s*:\s*(.+)", text)
    if not_after_match:
        info["notAfter"] = not_after_match.group(1).strip()

    # ── Serial Number ────────────────────────────
    serial_match = re.search(r"Serial Number:\s*\n?\s*(.+)", text)
    if serial_match:
        info["serialNumber"] = serial_match.group(1).strip().replace(":", "")

    # ── Subject Alt Names ────────────────────────
    san_match = re.search(r"Subject Alternative Name:\s*\n?\s*(.+)", text)
    if san_match:
        sans_raw = san_match.group(1)
        info["subjectAltName"] = re.findall(r"DNS:([^\s,]+)", sans_raw)
    print("parse open ssl:",info)
    return info


def _normalize_algorithm(raw: str) -> str:
    """Map OpenSSL algorithm string to a clean canonical name."""
    raw = raw.lower()
    if "ecdsa" in raw:
        return "ECDSA"
    if "rsa" in raw:
        return "RSA"
    if "ed25519" in raw:
        return "Ed25519"
    if "ed448" in raw:
        return "Ed448"
    if "dsa" in raw:
        return "DSA"
    if "ec" in raw:
        return "ECDSA"
    if "kyber" in raw:
        return "CRYSTALS-KYBER"
    if "dilithium" in raw:
        return "CRYSTALS-DILITHIUM"
    if "falcon" in raw:
        return "FALCON"
    if "sphincs" in raw:
        return "SPHINCS+"
    return raw.upper()


def _curve_to_bits(curve_name: str) -> Optional[int]:
    """Map EC curve OID name to key bit size."""
    mapping = {
        "prime256v1": 256, "secp256r1": 256, "secp256k1": 256,
        "secp384r1": 384,
        "secp521r1": 521,
        "brainpoolP256r1": 256,
        "brainpoolP384r1": 384,
        "brainpoolP512r1": 512,
        "X25519": 256, "X448": 448,
    }
    return mapping.get(curve_name)


def _parse_dn(dn_str: str) -> Dict[str, str]:
    """Parse a Distinguished Name string into a dict."""
    result = {}
    # Handle both comma-separated and slash-separated DNs
    parts = re.split(r",\s*(?=[A-Z])", dn_str.strip())
    for part in parts:
        kv = part.strip().split("=", 1)
        if len(kv) == 2:
            key_map = {
                "CN": "commonName",
                "O": "organizationName",
                "OU": "organizationalUnitName",
                "C": "countryName",
                "ST": "stateOrProvinceName",
                "L": "localityName",
            }
            k = key_map.get(kv[0].strip().upper(), kv[0].strip())
            result[k] = kv[1].strip()
    return result


def _get_negotiated_cipher_via_openssl(domain: str, port: int, starttls: Optional[str] = None) -> Dict[str, Any]:
    """
    Use `openssl s_client` to get the negotiated cipher suite name and TLS version.
    Returns dict with keys: cipher_name, tls_version
    """
    cmd = ["openssl", "s_client", "-connect", f"{domain}:{port}", "-servername", domain]
    if starttls:
        cmd += ["-starttls", starttls]

    result = run_command(cmd, timeout=15, input_data="Q\n")
    stdout = result["stdout"]

    cipher_name = None
    tls_version = None

    # Cipher line: "    Cipher    : ECDHE-RSA-AES256-GCM-SHA384"
    cipher_match = re.search(r"Cipher\s*:\s*(\S+)", stdout)
    if cipher_match:
        cipher_name = cipher_match.group(1)

    # Protocol line: "    Protocol  : TLSv1.3"
    proto_match = re.search(r"Protocol\s*:\s*(\S+)", stdout)
    if proto_match:
        tls_version = proto_match.group(1).replace("TLSv", "TLS ")

    return {"cipher_name": cipher_name, "tls_version": tls_version}


# ─────────────────────────────────────────
# TLS
# ─────────────────────────────────────────

# Ports to try when probing origin IPs for WAF/CDN bypass (kept small for speed)
BYPASS_PORTS = [443, 8443, 8080]

# Maximum seconds to spend on ALL bypass attempts per origin target
_BYPASS_TIME_BUDGET = 60

# CDN fingerprint headers — if ANY of these appear, we're still hitting an edge
_CDN_FINGERPRINT_HEADERS = {
    "cf-ray", "x-amz-cf-id", "x-cache", "x-cdn",
    "x-akamai-transformed", "x-fastly-request-id",
    "x-iinfo", "incap-sess-id", "visid_incap",  # Imperva/Incapsula
    "zscaler", "x-zscaler-tenant",              # Zscaler
    "x-tata-cdn",                               # Tata CDN
}
_CDN_SERVER_KEYWORDS = (
    "cloudflare", "akamai", "cloudfront", "fastly", 
    "imperva", "incapsula", "zscaler", "tata", "cdn"
)


def _confirm_bypass_succeeded(
    response_headers: dict,
    cert_serial: str = "",
    ct_serial: str = "",
) -> bool:
    """
    Returns True only if we're genuinely bypassing the CDN.
    Two checks:
      1. No CDN fingerprint headers in the response
      2. Cert serial matches what CT logs recorded (same leaf cert)
    """
    if response_headers:
        for h in response_headers:
            if h.lower() in _CDN_FINGERPRINT_HEADERS:
                logger.info(f"[bypass-check] CDN header detected: {h}")
                return False
        server = str(response_headers.get("server", "")).lower()
        if any(kw in server for kw in _CDN_SERVER_KEYWORDS):
            logger.info(f"[bypass-check] CDN server detected: {server}")
            return False

    # If CT serial is known, confirm we got the same cert
    if ct_serial and cert_serial and ct_serial != cert_serial:
        logger.warning(
            f"[bypass-check] Cert serial mismatch: got {cert_serial}, CT has {ct_serial}"
        )
        return False

    return True


def _http_probe_cdn_headers(
    origin_target: str,
    port: int,
    sni_domain: str,
) -> Dict[str, str]:
    """
    Open a TLS connection to origin_target:port, send a minimal HTTP/1.1 GET,
    and return the response headers as a dict.

    This is the bulletproof CDN detection: if the origin is still proxied
    through Cloudflare/Akamai/etc., the response will contain fingerprint
    headers like cf-ray, x-cache, server: cloudflare.

    Returns empty dict on failure (connection refused, timeout, etc.).
    """
    headers: Dict[str, str] = {}
    try:
        import ssl as _ssl

        context = _ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = _ssl.CERT_NONE

        with socket.create_connection((origin_target, port), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=sni_domain) as ssock:
                # Send minimal HTTP/1.1 request
                request = (
                    f"GET / HTTP/1.1\r\n"
                    f"Host: {sni_domain}\r\n"
                    f"Connection: close\r\n"
                    f"User-Agent: QuantumShield-Scanner/1.0\r\n"
                    f"\r\n"
                )
                ssock.sendall(request.encode("utf-8"))

                # Read response (up to 4KB — we only need the headers)
                response = b""
                try:
                    while len(response) < 4096:
                        chunk = ssock.recv(4096)
                        if not chunk:
                            break
                        response += chunk
                        # Stop once we have the full header block
                        if b"\r\n\r\n" in response:
                            break
                except socket.timeout:
                    pass

                # Parse headers from HTTP response
                text = response.decode("utf-8", errors="ignore")
                header_block = text.split("\r\n\r\n", 1)[0]
                for line in header_block.split("\r\n")[1:]:  # skip status line
                    if ":" in line:
                        key, _, value = line.partition(":")
                        headers[key.strip().lower()] = value.strip()

        logger.debug(
            f"[http-probe] {origin_target}:{port} returned {len(headers)} headers"
        )
    except Exception as e:
        logger.debug(f"[http-probe] {origin_target}:{port} failed: {e}")

    return headers

def scan_via_origin_bypass(
    sni_domain: str,
    origin_target: str,
    port: int = None,
    ports: List[int] = None,
    ct_serial: str = "",
) -> Dict[str, Any]:
    """
    WAF/CDN bypass TLS scan.

    Connect TCP to `origin_target` (an IP or internal host found from CT SANs)
    but send `sni_domain` as TLS SNI. The server returns its REAL leaf
    certificate — giving us the actual algorithm and key size.

    Fix 5: Tries multiple ports (BYPASS_PORTS) and returns the first
    confirmed bypass success.
    Fix 4: Validates bypass via CDN header fingerprinting + cert serial check.

    Strategy per port:
      1. openssl s_client -connect {origin_target}:{port} -servername {sni_domain}
      2. Python ssl fallback (also supports SNI override via wrap_socket)

    Returns same structure as run_tls_scan() so it drops in cleanly.
    """
    # Determine which ports to try
    if ports:
        try_ports = ports
    elif port:
        try_ports = [port]
    else:
        try_ports = BYPASS_PORTS

    start_time = time.time()

    for try_port in try_ports:
        # Enforce overall time budget
        elapsed = time.time() - start_time
        if elapsed > _BYPASS_TIME_BUDGET:
            logger.info(
                f"[origin-bypass] Time budget exhausted ({elapsed:.0f}s) "
                f"for {sni_domain} via {origin_target}, stopping"
            )
            break

        result = _try_bypass_on_port(sni_domain, origin_target, try_port, ct_serial)
        if result.get("certificates") and result.get("bypass_confirmed", False):
            logger.info(
                f"[origin-bypass] ✓ Confirmed bypass on port {try_port} "
                f"for {sni_domain} via {origin_target}"
            )
            return result
        elif result.get("certificates"):
            # Got a cert but bypass not confirmed (CDN headers present)
            logger.info(
                f"[origin-bypass] port {try_port} returned cert but bypass NOT confirmed "
                f"(still hitting CDN edge) for {sni_domain}"
            )
            # Continue trying other ports

    # All ports exhausted — return last result with error note
    return {
        "domain":          sni_domain,
        "origin_target":   origin_target,
        "port":            try_ports[-1] if try_ports else 443,
        "tls_version":     None,
        "cipher_suite":    None,
        "certificates":    [],
        "cipher_suites":   [],
        "error":           f"All ports failed or bypass not confirmed: {try_ports}",
        "scan_method":     "origin_bypass",
        "bypass_confirmed": False,
    }


def _try_bypass_on_port(
    sni_domain: str,
    origin_target: str,
    port: int,
    ct_serial: str = "",
) -> Dict[str, Any]:
    """Try a single port for origin bypass. Returns result dict."""
    result: Dict[str, Any] = {
        "domain":          sni_domain,
        "origin_target":   origin_target,
        "port":            port,
        "tls_version":     None,
        "cipher_suite":    None,
        "certificates":    [],
        "cipher_suites":   [],
        "error":           None,
        "scan_method":     "origin_bypass",
    }

    logger.info(f"[origin-bypass] {sni_domain} via {origin_target}:{port}")

    # ── Quick TCP pre-check: skip if port is unreachable ──────────────────────
    try:
        pre_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        pre_sock.settimeout(3)
        pre_result = pre_sock.connect_ex((origin_target, port))
        pre_sock.close()
        if pre_result != 0:
            logger.debug(f"[origin-bypass] TCP pre-check failed for {origin_target}:{port}, skipping")
            result["error"] = f"Port {port} unreachable"
            return result
    except Exception:
        logger.debug(f"[origin-bypass] TCP pre-check error for {origin_target}:{port}, skipping")
        result["error"] = f"Port {port} unreachable"
        return result

    # ── Method 1: OpenSSL CLI ─────────────────────────────────────────────────
    if _openssl_available():
        try:
            # Get cipher + TLS version
            cipher_cmd = [
                "openssl", "s_client",
                "-connect", f"{origin_target}:{port}",
                "-servername", sni_domain,
            ]
            cipher_result = run_command(cipher_cmd, timeout=5, input_data="Q\n")
            stdout = cipher_result["stdout"]

            cipher_match = re.search(r"Cipher\s*:\s*(\S+)", stdout)
            if cipher_match:
                result["cipher_suite"] = cipher_match.group(1)

            proto_match = re.search(r"Protocol\s*:\s*(\S+)", stdout)
            if proto_match:
                result["tls_version"] = proto_match.group(1).replace("TLSv", "TLS ")

            # Get certificate directly via origin target (skip domain — we already know it's behind CDN)
            pem = None
            fetch_cmd = [
                "openssl", "s_client",
                "-connect", f"{origin_target}:{port}",
                "-servername", sni_domain,
                "-showcerts",
            ]
            fetch_result = run_command(fetch_cmd, timeout=5, input_data="Q\n")
            match = re.search(
                r"(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)",
                fetch_result["stdout"],
                re.DOTALL,
            )
            if match:
                pem = match.group(1)

            if pem:
                cert_info = _parse_openssl_x509(pem)
                logger.info(
                    f"[origin-bypass] {sni_domain} via {origin_target}:{port} → "
                    f"algo={cert_info['algorithm']} key_size={cert_info['key_size']}"
                )
                cert_serial = cert_info.get("serialNumber", "")
                # HTTP-level CDN header probe for bulletproof confirmation
                http_headers = _http_probe_cdn_headers(origin_target, port, sni_domain)
                bypass_ok = _confirm_bypass_succeeded(http_headers, cert_serial, ct_serial)
                result["bypass_confirmed"] = bypass_ok
                result["certificates"].append({
                    "algorithm":      cert_info["algorithm"],
                    "key_size":       cert_info["key_size"],
                    "subject":        cert_info["subject"],
                    "issuer":         cert_info["issuer"],
                    "notAfter":       cert_info["notAfter"],
                    "serialNumber":   cert_info["serialNumber"],
                    "subjectAltName": cert_info["subjectAltName"],
                })
                if result["cipher_suite"]:
                    result["cipher_suites"].append({
                        "name":         result["cipher_suite"],
                        "tls_version":  result["tls_version"] or "",
                        "key_exchange": _extract_key_exchange(result["cipher_suite"]),
                        "port":         port,
                    })
                return result

        except Exception as e:
            logger.debug(f"[origin-bypass] openssl failed for {sni_domain}/{origin_target}: {e}")

    # ── Method 2: Python ssl with SNI override ────────────────────────────────
    try:
        import ssl as _ssl

        context = _ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode    = _ssl.CERT_NONE   # origin may not match CN

        with socket.create_connection((origin_target, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=sni_domain) as ssock:
                result["tls_version"] = ssock.version()
                cipher = ssock.cipher()
                if cipher:
                    result["cipher_suite"] = cipher[0]

                cert = ssock.getpeercert()
                if cert:
                    subject = dict(x[0] for x in cert.get("subject", []))
                    issuer  = dict(x[0] for x in cert.get("issuer", []))

                    # Python ssl cannot extract algorithm/key_size from getpeercert()
                    # But we at least get expiry + cipher-based inference
                    algo, key_size, _ = _infer_from_cipher_and_issuer(
                        cipher_name=result["cipher_suite"] or "",
                        issuer_str=" ".join([
                            issuer.get("organizationName", ""),
                            issuer.get("commonName", ""),
                        ]).strip(),
                    )

                    result["certificates"].append({
                        "algorithm":      algo,
                        "key_size":       key_size,
                        "subject":        subject,
                        "issuer":         issuer,
                        "notAfter":       cert.get("notAfter", ""),
                        "serialNumber":   cert.get("serialNumber", ""),
                        "subjectAltName": [v for _, v in cert.get("subjectAltName", [])],
                    })
                    cert_serial = cert.get("serialNumber", "")
                    # HTTP-level CDN header probe for bulletproof confirmation
                    http_headers = _http_probe_cdn_headers(origin_target, port, sni_domain)
                    bypass_ok = _confirm_bypass_succeeded(http_headers, cert_serial, ct_serial)
                    result["bypass_confirmed"] = bypass_ok
                    logger.info(
                        f"[origin-bypass/pyssl] {sni_domain} via {origin_target}:{port} → "
                        f"algo={algo} (cipher-inferred) bypass_confirmed={bypass_ok}"
                    )

                if result["cipher_suite"]:
                    result["cipher_suites"].append({
                        "name":         result["cipher_suite"],
                        "tls_version":  result["tls_version"] or "",
                        "key_exchange": _extract_key_exchange(result["cipher_suite"]),
                        "port":         port,
                    })

    except Exception as e:
        result["error"] = str(e)
        logger.debug(f"[origin-bypass] python ssl failed for {sni_domain}/{origin_target}: {e}")

    return result


def _infer_from_cipher_and_issuer(
    cipher_name: str,
    issuer_str: str,
) -> Tuple[str, int, str]:
    """
    Infer (algorithm, key_size, source) from cipher suite + issuer string.
    Used when openssl is unavailable and Python ssl can't extract key algo.
    """
    cu = cipher_name.upper()
    iu = issuer_str.upper()

    # ── Fix 6: TLS 1.3 suites don't encode key exchange or auth algo ──────
    # TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, etc.
    # Auth algo comes from the cert, not the cipher suite name.
    # Fall through to issuer-based inference instead of returning wrong default.
    if cu.startswith("TLS_AES_") or cu.startswith("TLS_CHACHA20_"):
        pass  # skip cipher-based inference, use issuer below
    elif "ECDHE_ECDSA" in cu or "ECDH_ECDSA" in cu:
        return "ECDSA", 256, "cipher_suite"
    elif "ECDHE_RSA" in cu or "ECDH_RSA" in cu:
        # Key exchange is ECDHE but the *cert* is RSA-signed
        return "RSA", 2048, "cipher_suite"
    elif cu.startswith("TLS_RSA_WITH") or cu.startswith("RSA_WITH"):
        return "RSA", 2048, "cipher_suite"

    # Issuer-based inference (fallback for TLS 1.3 and unknown ciphers)
    if "ECC" in iu or "ECDSA" in iu:
        return "ECDSA", 384 if "384" in iu else 256, "issuer_name"
    if "RSA" in iu:
        m = re.search(r"RSA[- ]?(\d{4})", iu)
        return "RSA", int(m.group(1)) if m else 2048, "issuer_name"

    return "RSA", 2048, "default"


def run_tls_scan(domain: str, port: int = 443, starttls: Optional[str] = None) -> Dict[str, Any]:
    """
    Attempt TLS scan in priority order:
      1. testssl.sh  (most comprehensive)
      2. openssl CLI  (real data: algorithm, key_size, issuer, cipher suite)
      3. Python ssl module fallback (uses cryptography lib for real algo/key_size)

    Falls back to the next method if the current one returns no certificates.
    """
    # testssl.sh integration
    if is_tool_available("testssl.sh"):
        result = _run_testssl(domain, port, starttls)
        if isinstance(result, dict) and result.get("certificates"):
            return result

    if _openssl_available():
        result = _openssl_tls_scan(domain, port, starttls)
        if result.get("certificates"):
            return result
        logger.info(f"[tls] openssl returned no certs for {domain}:{port}, trying python ssl")

    return _python_tls_scan(domain, port)


def _openssl_tls_scan(domain: str, port: int = 443, starttls: Optional[str] = None) -> Dict[str, Any]:
    """
    Full TLS scan using OpenSSL CLI:
      - Retrieves the certificate PEM
      - Parses algorithm, key_size, subject, issuer, SANs, expiry
      - Retrieves the negotiated cipher suite and TLS version
    """
    result = {
        "domain": domain,
        "port": port,
        "tls_version": None,
        "cipher_suite": None,
        "certificates": [],
        "cipher_suites": [],
        "supported_versions": [],
        "error": None,
        "scan_method": "openssl_cli",
    }

    try:
        # ── Step 1: Get negotiated cipher & TLS version ──
        cipher_info = _get_negotiated_cipher_via_openssl(domain, port, starttls)
        result["tls_version"] = cipher_info.get("tls_version")
        result["cipher_suite"] = cipher_info.get("cipher_name")

        # ── Step 2: Get certificate PEM ──
        pem = _get_cert_pem_via_openssl(domain, port, starttls)

        if pem:
            # ── Step 3: Parse certificate details ──
            cert_info = _parse_openssl_x509(pem)

            logger.info(
                f"[openssl] {domain}:{port} → algo={cert_info['algorithm']} "
                f"key_size={cert_info['key_size']} "
                f"issuer={cert_info['issuer'].get('organizationName', 'Unknown')}"
            )

            result["certificates"].append({
                "algorithm":      cert_info["algorithm"],
                "key_size":       cert_info["key_size"],
                "subject":        cert_info["subject"],
                "issuer":         cert_info["issuer"],
                "notAfter":       cert_info["notAfter"],
                "serialNumber":   cert_info["serialNumber"],
                "subjectAltName": cert_info["subjectAltName"],
            })
        else:
            logger.warning(f"[openssl] Could not retrieve PEM for {domain}:{port}, cascading to python ssl")
            return _python_tls_scan(domain, port)

    except Exception as e:
        logger.error(f"[openssl] TLS scan error for {domain}:{port}: {e}, cascading to python ssl")
        return _python_tls_scan(domain, port)

    print("open ssl tls scan result:",result)

    return result


def _extract_algo_from_der(der_bytes: bytes) -> Tuple[Optional[str], Optional[int]]:
    """
    Parse a DER-encoded certificate using the `cryptography` library to
    extract the REAL public key algorithm and key size.
    Returns (algorithm, key_size) or (None, None) if parsing fails.
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import (
            rsa, ec, ed25519, ed448, dsa,
        )

        cert = x509.load_der_x509_certificate(der_bytes)
        pub_key = cert.public_key()

        if isinstance(pub_key, rsa.RSAPublicKey):
            return "RSA", pub_key.key_size
        if isinstance(pub_key, ec.EllipticCurvePublicKey):
            return "ECDSA", pub_key.key_size
        if isinstance(pub_key, ed25519.Ed25519PublicKey):
            return "Ed25519", 256
        if isinstance(pub_key, ed448.Ed448PublicKey):
            return "Ed448", 448
        if isinstance(pub_key, dsa.DSAPublicKey):
            return "DSA", pub_key.key_size

        return None, None
    except ImportError:
        logger.debug("[pyssl] cryptography library not available for DER parsing")
        return None, None
    except Exception as e:
        logger.debug(f"[pyssl] DER cert parsing failed: {e}")
        return None, None


def _python_tls_scan(domain: str, port: int = 443) -> Dict[str, Any]:
    """
    Fallback TLS scan using Python's ssl module.
    Uses getpeercert(binary_form=True) + `cryptography` library to extract
    the REAL algorithm and key_size from the DER-encoded certificate.
    Falls back to cipher-based inference if cryptography is unavailable.
    """
    result = {
        "domain": domain,
        "port": port,
        "tls_version": None,
        "cipher_suite": None,
        "certificates": [],
        "cipher_suites": [],
        "supported_versions": [],
        "error": None,
        "scan_method": "python_ssl",
    }

    try:
        context = ssl.create_default_context()
        # Allow connection even if cert verification fails (self-signed, etc.)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((domain, port), timeout=10) as sock:

            with context.wrap_socket(sock, server_hostname=domain) as ssock:

                result["tls_version"] = ssock.version()

                # cipher() returns (name, protocol, bits)
                cipher = ssock.cipher()
                cipher_name = ""
                if cipher:
                    cipher_name = cipher[0]
                    result["cipher_suite"] = cipher_name

                # ── Get DER cert for real algo/key_size via cryptography lib ──
                der_bytes = ssock.getpeercert(binary_form=True)
                real_algo, real_key_size = None, None
                if der_bytes:
                    real_algo, real_key_size = _extract_algo_from_der(der_bytes)
                    if real_algo:
                        logger.info(
                            f"[pyssl] {domain}:{port} → real algo={real_algo} "
                            f"key_size={real_key_size} (from DER cert)"
                        )
                        result["scan_method"] = "python_ssl_real"

                # ── Get human-readable cert fields ──
                # Re-connect with verification for getpeercert() readable fields,
                # or parse from DER
                subject = {}
                issuer = {}
                not_after = ""
                serial = ""
                sans = []

                try:
                    # Try to extract from DER via cryptography
                    if der_bytes:
                        from cryptography import x509
                        cert_obj = x509.load_der_x509_certificate(der_bytes)
                        # Subject
                        for attr in cert_obj.subject:
                            oid_name = attr.oid._name
                            key_map = {
                                "commonName": "commonName",
                                "organizationName": "organizationName",
                                "countryName": "countryName",
                            }
                            if oid_name in key_map:
                                subject[key_map[oid_name]] = attr.value
                        # Issuer
                        for attr in cert_obj.issuer:
                            oid_name = attr.oid._name
                            key_map = {
                                "commonName": "commonName",
                                "organizationName": "organizationName",
                                "countryName": "countryName",
                            }
                            if oid_name in key_map:
                                issuer[key_map[oid_name]] = attr.value
                        # Expiry
                        not_after = cert_obj.not_valid_after_utc.strftime(
                            "%b %d %H:%M:%S %Y"
                        )
                        # Serial
                        serial = format(cert_obj.serial_number, "x")
                        # SANs
                        try:
                            san_ext = cert_obj.extensions.get_extension_for_class(
                                x509.SubjectAlternativeName
                            )
                            sans = san_ext.value.get_values_for_type(x509.DNSName)
                        except x509.ExtensionNotFound:
                            pass
                except ImportError:
                    # cryptography not available — try getpeercert() with verify
                    try:
                        ctx2 = ssl.create_default_context()
                        with socket.create_connection((domain, port), timeout=10) as s2:
                            with ctx2.wrap_socket(s2, server_hostname=domain) as ss2:
                                cert = ss2.getpeercert()
                                if cert:
                                    subject = dict(x[0] for x in cert.get("subject", []))
                                    issuer = dict(x[0] for x in cert.get("issuer", []))
                                    not_after = cert.get("notAfter", "")
                                    serial = cert.get("serialNumber", "")
                                    sans = [v for _, v in cert.get("subjectAltName", [])]
                    except Exception:
                        pass
                except Exception as parse_err:
                    logger.debug(f"[pyssl] cert field parsing failed: {parse_err}")

                # ── Fallback: infer algo from cipher + issuer if no real data ──
                if not real_algo:
                    issuer_str = " ".join([
                        issuer.get("organizationName", ""),
                        issuer.get("commonName", ""),
                    ]).strip()
                    real_algo, real_key_size, _ = _infer_from_cipher_and_issuer(
                        cipher_name, issuer_str
                    )
                    result["scan_method"] = "python_ssl_inferred"
                    logger.info(
                        f"[pyssl] {domain}:{port} → inferred algo={real_algo} "
                        f"key_size={real_key_size} (from cipher+issuer)"
                    )

                result["certificates"].append({
                    "algorithm":      real_algo,
                    "key_size":       real_key_size,
                    "subject":        subject,
                    "issuer":         issuer,
                    "notAfter":       not_after,
                    "serialNumber":   serial,
                    "subjectAltName": sans,
                })

    except Exception as e:
        logger.error(f"[pyssl] TLS scan error for {domain}:{port}: {e}")
        result["error"] = str(e)

    return result


def _parse_testssl_json(data: Any, domain: str, port: int) -> Dict[str, Any]:
    """
    Parse the list output of testssl.sh into our unified Dict format.
    Handles the case where data is a list of findings rather than a dict.
    """
    result = {
        "domain": domain,
        "port": port,
        "tls_version": None,
        "cipher_suite": None,
        "certificates": [],
        "cipher_suites": [],
        "supported_versions": [],
        "error": None,
        "scan_method": "testssl",
    }

    if not isinstance(data, list):
        return result

    # Standard cert fields
    cert = {
        "algorithm": "RSA",
        "key_size": 2048,
        "subject": {},
        "issuer": {},
        "notAfter": "",
        "serialNumber": "",
        "subjectAltName": [],
    }
    
    found_cert = False
    
    for entry in data:
        eid = entry.get("id", "")
        finding = entry.get("finding", "")
        
        # Mapping certificate details
        if eid == "cert_keySize":
            m = re.search(r"(\d+)", finding)
            if m: cert["key_size"] = int(m.group(1))
            found_cert = True
        elif eid == "cert_algorithm":
            cert["algorithm"] = finding
            found_cert = True
        elif eid == "cert_issuer":
            cert["issuer"]["commonName"] = finding
            found_cert = True
        elif eid == "cert_commonName":
            cert["subject"]["commonName"] = finding
            found_cert = True
        elif eid == "cert_notAfter":
            cert["notAfter"] = finding
            found_cert = True
        elif eid == "cert_serial":
            cert["serialNumber"] = finding
            found_cert = True
            
        # Mapping Protocols (pick highest)
        if eid.startswith("protocol_") and "offered" in finding.lower():
            proto = eid.replace("protocol_", "").replace("_", ".")
            # Naive "highest" selection: basically if we haven't found one yet or it's TLS 1.3
            if not result["tls_version"] or "1.3" in proto:
                result["tls_version"] = proto
        
        # In case protocol_ is missing, check if it's in finding text from protocols test
        if eid in ["SSLv2", "SSLv3", "TLS1", "TLS1_1", "TLS1_2", "TLS1_3"] and "offered" in finding.lower():
            proto_sh = eid.replace("TLS", "TLS ").replace("SSL", "SSL ")
            if not result["tls_version"] or "1.3" in proto_sh:
                 result["tls_version"] = proto_sh

        # Mapping Ciphers
        if eid.startswith("cipher-"):
            # testssl findings are often: "   ECDH 256   AES         256      TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
            # We want the RFC name at the end (e.g. TLS_...)
            cname = finding.strip()
            # If it's multi-column, try to take the last part that looks like a cipher name
            parts = cname.split()
            if parts:
                # Look for something starting with TLS_ or containing _WITH_
                for p in reversed(parts):
                    if p.startswith("TLS_") or "_WITH_" in p or "-" in p:
                        cname = p
                        break
            
            if cname:
                result["cipher_suites"].append({
                    "name": cname,
                    "tls_version": result["tls_version"] or "Unknown",
                    "key_exchange": _extract_key_exchange(cname),
                    "is_quantum_vulnerable": True, # testssl usually doesn't scan PQC yet
                    "quantum_risk": 9.0 if "RSA" in cname or "ECDSA" in cname else 5.0,
                })
                # Set as primary if not set
                if not result["cipher_suite"]:
                    result["cipher_suite"] = cname

    if found_cert:
        result["certificates"].append(cert)
        
    return result


def _run_testssl(domain: str, port: int = 443, starttls: Optional[str] = None) -> Dict[str, Any]:
    # Use a unique filename for this scan to avoid race conditions
    json_path = f"/tmp/testssl_{int(time.time())}.json"
    cmd = ["testssl.sh", "--jsonfile", json_path, "--quiet"]
    if starttls:
        cmd.extend(["-t", starttls])
    cmd.append(f"{domain}:{port}")
    
    logger.info(f"[testssl] Running scan for {domain}:{port}...")
    run_command(cmd, timeout=300)

    try:
        if os.path.exists(json_path):
            with open(json_path, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if not content:
                    logger.warning(f"[testssl] JSON file for {domain} is empty")
                    raise ValueError("Empty JSON output")
                
                try:
                    raw_data = json.loads(content)
                except json.JSONDecodeError:
                    # Fix trailing commas
                    content = re.sub(r',\s*([\]}])', r'\1', content)
                    # Fix adjacent arrays typical from testssl multiple tests
                    content = re.sub(r'\]\s*\[', ',', content)
                    try:
                        raw_data = json.loads(content)
                    except json.JSONDecodeError:
                        raw_data = []
                        # Extract objects blindly as last resort
                        for m in re.finditer(r'\{[^{}]+\}', content):
                            try:
                                raw_data.append(json.loads(m.group(0)))
                            except:
                                pass
                
            # Cleanup
            try: os.remove(json_path)
            except: pass
            
            return _parse_testssl_json(raw_data, domain, port)
    except (json.JSONDecodeError, ValueError) as json_err:
        logger.error(f"[testssl] Malformed JSON for {domain}: {json_err}")
        # Cleanup on failure
        if os.path.exists(json_path):
            try: os.remove(json_path)
            except: pass
    except Exception as e:
        logger.error(f"[testssl] Error reading results for {domain}: {e}")
        
    # Fallback if testssl failed or produced invalid data
    logger.info(f"[testssl] Falling back to OpenSSL/Python for {domain}:{port}")
    if _openssl_available():
        return _openssl_tls_scan(domain, port, starttls)
    return _python_tls_scan(domain, port)


# ─────────────────────────────────────────
# MAIN SCAN
# ─────────────────────────────────────────

def scan_asset(domain: str, progress_callback=None) -> Dict[str, Any]:

    logger.info(f"Scanning {domain}")

    result = {
        "domain": domain,
        "resolved_ips": [],
        "open_ports": [],
        "protocol": "UNKNOWN",
        "is_cdn": False,
        "tls_data": {},
        "certificates": [],
        "cipher_suites": [],
        "findings": [],
        "server_software": None,
        "cdn_provider": None,
    }

    # DNS
    ips = resolve_dns(domain)
    result["resolved_ips"] = ips

    if not ips:
        return result

    target_ip = ips[0]

    # CDN
    is_cdn, cdn_provider = _detect_cdn(domain, target_ip)
    result["is_cdn"] = is_cdn
    result["cdn_provider"] = cdn_provider

    # PORT SCAN
    nmap_data = run_nmap_scan(target_ip if not result["is_cdn"] else domain)
    result["open_ports"] = nmap_data.get("open_ports", [])

    # ───────────────
    # PROTOCOL DETECTION
    # ───────────────
    port_numbers = set(p["port"] for p in result["open_ports"])

    if 443 in port_numbers or 8443 in port_numbers:
        result["protocol"] = "HTTPS"
    elif 465 in port_numbers or 587 in port_numbers or 25 in port_numbers:
        result["protocol"] = "SMTP"
    elif 993 in port_numbers or 143 in port_numbers:
        result["protocol"] = "IMAP"
    elif 995 in port_numbers or 110 in port_numbers:
        result["protocol"] = "POP3"
    elif 22 in port_numbers:
        result["protocol"] = "SSH"
    elif 990 in port_numbers or 21 in port_numbers:
        result["protocol"] = "FTPS"
    elif 1194 in port_numbers or 1723 in port_numbers or 500 in port_numbers:
        result["protocol"] = "VPN"
    else:
        result["protocol"] = "UNKNOWN"

    # ───────────────────────────────────────────────
    # TLS SCAN – run on ALL TLS-capable open ports
    # Including UNKNOWN protocol: try every open port
    # ───────────────────────────────────────────────
    primary_tls_data = None

    # Determine which open ports to attempt TLS on
    tls_scan_targets = []

    for port_num in sorted(port_numbers):
        if port_num in TLS_PORTS:
            tls_scan_targets.append((port_num, TLS_PORTS[port_num].get("starttls")))

    # For UNKNOWN protocol — also try any open port not in TLS_PORTS
    if result["protocol"] == "UNKNOWN":
        for port_num in sorted(port_numbers):
            if port_num not in TLS_PORTS:
                tls_scan_targets.append((port_num, None))

    for scan_port, starttls in tls_scan_targets:

        # SSH does not use TLS — skip cert extraction but note the port
        if scan_port == 22:
            logger.info(f"[scan] Skipping TLS cert extraction for SSH port 22 on {domain}")
            continue

        logger.info(f"[scan] TLS scanning {domain}:{scan_port} (starttls={starttls})")

        try:
            tls_data = run_tls_scan(domain, scan_port, starttls)
        except Exception as e:
            logger.warning(f"[scan] TLS scan failed on {domain}:{scan_port}: {e}")
            continue

        # Use the first successful TLS result as primary (highest-priority port)
        if primary_tls_data is None and (tls_data.get("certificates") or tls_data.get("cipher_suite")):
            primary_tls_data = tls_data
            result["tls_data"] = tls_data

        # Collect certificates (deduplicate by serialNumber)
        seen_serials = {c.get("serialNumber") for c in result["certificates"]}
        for cert in tls_data.get("certificates", []):
            serial = cert.get("serialNumber", "")
            if serial not in seen_serials:
                result["certificates"].append(cert)
                seen_serials.add(serial)

        # Collect cipher suites (negotiated + full list if available)
        seen_ciphers = {cs.get("name") for cs in result["cipher_suites"]}
        
        # 1. Add negotiated one if not already there
        if tls_data.get("cipher_suite"):
            cname = tls_data["cipher_suite"]
            if cname not in seen_ciphers:
                result["cipher_suites"].append({
                    "name":         cname,
                    "tls_version":  tls_data.get("tls_version", ""),
                    "key_exchange": _extract_key_exchange(cname),
                    "port":         scan_port,
                })
                seen_ciphers.add(cname)

        # 2. Add the full enumerated list (testssl.sh)
        for cs in tls_data.get("cipher_suites", []):
            if cs.get("name") not in seen_ciphers:
                cs["port"] = scan_port
                result["cipher_suites"].append(cs)
                seen_ciphers.add(cs.get("name"))

    # ───────────────────────────────────────────────
    # SERVER SOFTWARE IDENTIFICATION
    # ───────────────────────────────────────────────
    # Try to get 'Server' header from anyone we reached
    headers = _http_probe_cdn_headers(target_ip, 443, domain)
    if not headers:
        headers = _http_probe_cdn_headers(target_ip, 80, domain)
    
    if headers:
        result["server_software"] = headers.get("server")
        if not result["server_software"] and headers.get("x-powered-by"):
            result["server_software"] = f"Powered by {headers.get('x-powered-by')}"
    print("scan asset:",result)
    return result


# ─────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────

def _detect_cdn(domain: str, ip: str) -> Tuple[bool, Optional[str]]:
    # 1. Check HTTP response headers (most reliable)
    headers = _http_probe_cdn_headers(ip, 443, domain)
    if not headers:
        headers = _http_probe_cdn_headers(ip, 80, domain)
        
    if headers:
        for h, val in headers.items():
            if h.lower() in _CDN_FINGERPRINT_HEADERS:
                # Try to map header to a friendly name
                provider = _map_header_to_cdn(h, val)
                return True, provider
        
        server = str(headers.get("server", "")).lower()
        for kw in _CDN_SERVER_KEYWORDS:
            if kw in server:
                return True, kw.capitalize()

    # 2. Fallback to reverse DNS check
    try:
        hostname = socket.gethostbyaddr(ip)[0].lower()
        for kw in _CDN_SERVER_KEYWORDS:
            if kw in hostname:
                return True, kw.capitalize()
    except Exception:
        pass

    return False, None


def _map_header_to_cdn(header: str, value: str) -> str:
    h = header.lower()
    if h == "cf-ray": return "Cloudflare"
    if "amz-cf" in h: return "CloudFront"
    if "akamai" in h: return "Akamai"
    if "fastly" in h: return "Fastly"
    if "incap" in h or "visid_incap" in h: return "Imperva"
    if "zscaler" in h: return "Zscaler"
    return "Generic CDN/WAF"


def _extract_key_exchange(cipher_name: str) -> str:
    name = cipher_name.upper()
    if "ECDHE" in name:
        return "ECDHE"
    if "DHE" in name:
        return "DHE"
    if "RSA" in name:
        return "RSA"
    if "ECDH" in name:
        return "ECDH"
    return "UNKNOWN"