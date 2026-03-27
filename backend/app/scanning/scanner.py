"""
Scanning Engine - Main orchestrator
Wraps Nmap, OpenSSL CLI, SSLyze, and Subfinder with a smart fallback to
Python ssl module for environments where tools are unavailable.

Key improvements:
  - Real algorithm & key size extracted via `openssl s_client` + `openssl x509`
  - Real issuer name extracted from certificate
  - TLS scan runs on ALL TLS-capable ports (443, 8443, 465, 587, 993, 995, 990, etc.)
  - UNKNOWN protocol domains still attempt TLS scan on any open port
  - Cipher suite extracted via Python ssl interface (real negotiated cipher)
"""
import subprocess
import json
import os
import re
import socket
import ssl
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
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

    result = run_command(
        ["nmap", "-sV", "-p", ports, "--open", "-T4", "--script", "ssl-cert,ssl-enum-ciphers", target],
        timeout=120
    )

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

    open_ports = []

    for port, service in ports.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)

            result = sock.connect_ex((target, port))

            sock.close()

            if result == 0:
                open_ports.append({
                    "port": port,
                    "service": service,
                    "state": "open"
                })

        except Exception:
            pass

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

def run_tls_scan(domain: str, port: int = 443, starttls: Optional[str] = None) -> Dict[str, Any]:
    """
    Attempt TLS scan in priority order:
      1. testssl.sh  (most comprehensive)
      2. openssl CLI  (real data: algorithm, key_size, issuer, cipher suite)
      3. Python ssl module fallback
    """
    if is_tool_available("testssl.sh"):
        return _run_testssl(domain, port)

    if _openssl_available():
        return _openssl_tls_scan(domain, port, starttls)

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
            logger.warning(f"[openssl] Could not retrieve PEM for {domain}:{port}")
            result["error"] = "Could not retrieve certificate PEM"

    except Exception as e:
        logger.error(f"[openssl] TLS scan error for {domain}:{port}: {e}")
        result["error"] = str(e)

    return result


def _python_tls_scan(domain: str, port: int = 443) -> Dict[str, Any]:
    """
    Fallback TLS scan using Python's ssl module.
    Extracts cipher suite name and TLS version from the negotiated connection.
    Note: Python ssl does NOT expose algorithm or key_size from getpeercert(),
    so those will be None and must be inferred later.
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

        with socket.create_connection((domain, port), timeout=10) as sock:

            with context.wrap_socket(sock, server_hostname=domain) as ssock:

                result["tls_version"] = ssock.version()

                # cipher() returns (name, protocol, bits)
                cipher = ssock.cipher()
                if cipher:
                    result["cipher_suite"] = cipher[0]

                cert = ssock.getpeercert()

                if cert:
                    subject = dict(x[0] for x in cert.get("subject", []))
                    issuer  = dict(x[0] for x in cert.get("issuer", []))

                    result["certificates"].append({
                        "algorithm":      None,   # Python ssl cannot extract this
                        "key_size":       None,   # Python ssl cannot extract this
                        "subject":        subject,
                        "issuer":         issuer,
                        "notAfter":       cert.get("notAfter", ""),
                        "serialNumber":   cert.get("serialNumber", ""),
                        "subjectAltName": [v for _, v in cert.get("subjectAltName", [])],
                    })

    except Exception as e:
        result["error"] = str(e)

    return result


def _run_testssl(domain: str, port: int = 443) -> Dict[str, Any]:
    run_command(
        ["testssl.sh", "--jsonfile", "/tmp/testssl.json", "--quiet", f"{domain}:{port}"],
        timeout=180
    )

    try:
        with open("/tmp/testssl.json") as f:
            return json.load(f)
    except Exception:
        if _openssl_available():
            return _openssl_tls_scan(domain, port)
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
    }

    # DNS
    ips = resolve_dns(domain)
    result["resolved_ips"] = ips

    if not ips:
        return result

    target_ip = ips[0]

    # CDN
    result["is_cdn"] = _detect_cdn(domain, target_ip)

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

        # Collect cipher suites
        if tls_data.get("cipher_suite"):
            cipher_entry = {
                "name":         tls_data["cipher_suite"],
                "tls_version":  tls_data.get("tls_version", ""),
                "key_exchange": _extract_key_exchange(tls_data["cipher_suite"]),
                "port":         scan_port,
            }
            result["cipher_suites"].append(cipher_entry)

    return result


# ─────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────

def _detect_cdn(domain: str, ip: str) -> bool:
    cdn_keywords = ["cloudflare", "akamai", "fastly", "cloudfront", "cdn"]
    try:
        hostname = socket.gethostbyaddr(ip)[0].lower()
        return any(k in hostname for k in cdn_keywords)
    except Exception:
        return False


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