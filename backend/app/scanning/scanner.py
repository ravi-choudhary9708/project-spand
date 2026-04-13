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
import ipaddress
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
# RFC 1918 + reserved private ranges
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),       # Class A private
    ipaddress.ip_network("172.16.0.0/12"),     # Class B private
    ipaddress.ip_network("192.168.0.0/16"),    # Class C private
    ipaddress.ip_network("127.0.0.0/8"),       # Loopback
    ipaddress.ip_network("169.254.0.0/16"),    # Link-local
    ipaddress.ip_network("::1/128"),           # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),          # IPv6 ULA
]

def _is_internal_ip(ip: str) -> bool:
    """
    Returns True if ip is a private/reserved address (RFC 1918 / RFC 4193).
    These addresses should never appear as the resolved IP of a public-facing
    domain. If they do, it means the domain is internal-only and was discovered
    via CT logs or subfinder from internal cert SANs.
    """
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in network for network in _PRIVATE_NETWORKS)
    except ValueError:
        return False

# Regex to identify IPv4 addresses
_IPv4_RE = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")



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
    print("subdomains:",subdomains)
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
        ips = list(set([r[4][0] for r in results]))
        # Prioritize IPv4: sort IPs so colons (IPv6) come last
        ips.sort(key=lambda x: ":" in x)
        return ips
    except Exception:
        return []


# ─────────────────────────────────────────
# NMAP
# ─────────────────────────────────────────

def run_nmap_scan(target: str) -> Dict[str, Any]:

    if not is_tool_available("nmap"):
        logger.warning("nmap not found, using fallback scan")
        return _nmap_fallback(target)

    # Added port 53 for DNS detection (not in fallback to save time)
    ports = "443,8443,25,587,465,143,993,110,995,21,990,22,1194,1723,500,53"

    # Fast SYN scan — service version detection and SSL scripts are NOT needed
    # because TLS/cert data is gathered separately via openssl/python ssl.
    # Detect if target is IPv6
    is_ipv6 = ":" in target and not target.startswith("[")
    
    cmd = ["nmap", "-sS", "-T4", "--top-ports", "1000", "-n", "-Pn", "--open", "--min-rate", "1000"]
    if is_ipv6:
        cmd.append("-6")
    cmd.append(target)

    result = run_command(cmd)
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
            # Determine address family
            family = socket.AF_INET6 if ":" in target else socket.AF_INET
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.settimeout(2)
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
    print("namp output ports:",open_ports)
    return {"target": target, "open_ports": open_ports, "raw": output[:2000]}


# ─────────────────────────────────────────
# OPENSSL CLI - Real Algorithm & Key Size
# ─────────────────────────────────────────

def _openssl_available() -> bool:
    return is_tool_available("openssl")


def _get_cert_pem_via_openssl(domain: str, port: int, starttls: Optional[str] = None, ip_address: Optional[str] = None) -> Optional[str]:
    """
    Use `openssl s_client` to retrieve the PEM certificate from a server.
    Supports STARTTLS for SMTP/IMAP/POP3/FTP.
    Returns the PEM string or None on failure.
    """
    target = f"{ip_address}:{port}" if ip_address else f"{domain}:{port}"
    cmd = ["openssl", "s_client", "-connect", target, "-servername", domain, "-showcerts"]
    if starttls:
        cmd += ["-starttls", starttls]

    result = run_command(cmd, timeout=15, input_data="Q\n")

    if result["returncode"] not in (0, 1) or not result["stdout"]:
        # Try without SNI (IP targets, unknown protocol)
        cmd2 = ["openssl", "s_client", "-connect", target, "-showcerts"]
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
    if not dn_str:
        return result

    # Handle both comma-separated and slash-separated DNs
    # Slash-separated: /C=IN/O=PNB/...
    # Comma-separated: C=IN, O=PNB, ...
    if dn_str.startswith("/"):
        parts = dn_str.strip("/").split("/")
    else:
        parts = re.split(r",\s*(?=[A-Z(])", dn_str.strip())

    for part in parts:
        if "=" not in part:
            continue
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


def _get_negotiated_cipher_via_openssl(domain: str, port: int, starttls: Optional[str] = None, ip_address: Optional[str] = None) -> Dict[str, Any]:
    """
    Use `openssl s_client` to get the negotiated cipher suite name and TLS version.
    Returns dict with keys: cipher_name, tls_version
    """
    target = f"{ip_address}:{port}" if ip_address else f"{domain}:{port}"
    cmd = ["openssl", "s_client", "-connect", target, "-servername", domain]
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
# SSLYZE — Full Cipher Suite Enumeration
# ─────────────────────────────────────────

def _sslyze_available() -> bool:
    """Check if SSLyze can be imported."""
    try:
        import sslyze  # noqa: F401
        return True
    except ImportError:
        return False


def _sslyze_cipher_enum(
    domain: str,
    port: int = 443,
    starttls: Optional[str] = None,
    ip_address: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Use SSLyze's Python API to enumerate ALL cipher suites accepted by the
    server across every TLS version (SSL 2.0 → TLS 1.3).

    Args:
        domain:     Hostname (used as SNI even if ip_address is given)
        port:       TLS port
        starttls:   STARTTLS protocol name (smtp, imap, pop3, ftp) or None
        ip_address: If set, connect to this IP but use `domain` as SNI
                    (used for CDN/WAF bypass scans)

    Returns:
        List of cipher suite dicts:
        [{"name": ..., "tls_version": ..., "key_exchange": ..., "port": ...}, ...]
        Empty list on any failure (graceful degradation).
    """
    try:
        from sslyze import (
            Scanner,
            ServerScanRequest,
            ServerNetworkLocation,
            ServerNetworkConfiguration,
            ScanCommand,
            ServerScanStatusEnum,
            ScanCommandAttemptStatusEnum,
        )
        from sslyze import ProtocolWithOpportunisticTlsEnum
    except ImportError:
        logger.debug("[sslyze] SSLyze not installed, skipping cipher enumeration")
        return []

    try:
        # ── Build server location ──
        location_kwargs = {"hostname": domain, "port": port}
        if ip_address:
            location_kwargs["ip_address"] = ip_address
        server_location = ServerNetworkLocation(**location_kwargs)

        # ── Build network configuration (STARTTLS + SNI override) ──
        net_config_kwargs = {
            "tls_server_name_indication": domain,
            "network_timeout": 10,
            "network_max_retries": 1,
        }

        # Map our starttls strings → SSLyze ProtocolWithOpportunisticTlsEnum
        _STARTTLS_MAP = {
            "smtp": ProtocolWithOpportunisticTlsEnum.SMTP,
            "imap": ProtocolWithOpportunisticTlsEnum.IMAP,
            "pop3": ProtocolWithOpportunisticTlsEnum.POP3,
            "ftp":  ProtocolWithOpportunisticTlsEnum.FTP,
        }
        if starttls and starttls.lower() in _STARTTLS_MAP:
            net_config_kwargs["tls_opportunistic_encryption"] = _STARTTLS_MAP[starttls.lower()]

        network_config = ServerNetworkConfiguration(**net_config_kwargs)

        # ── Only request cipher suite scan commands (fast) ──
        cipher_commands = {
            ScanCommand.SSL_2_0_CIPHER_SUITES,
            ScanCommand.SSL_3_0_CIPHER_SUITES,
            ScanCommand.TLS_1_0_CIPHER_SUITES,
            ScanCommand.TLS_1_1_CIPHER_SUITES,
            ScanCommand.TLS_1_2_CIPHER_SUITES,
            ScanCommand.TLS_1_3_CIPHER_SUITES,
        }

        scan_request = ServerScanRequest(
            server_location=server_location,
            network_configuration=network_config,
            scan_commands=cipher_commands,
        )

        scanner = Scanner(
            per_server_concurrent_connections_limit=3,
            concurrent_server_scans_limit=1,
        )
        scanner.queue_scans([scan_request])

        # ── Process results ──
        all_suites: List[Dict[str, Any]] = []

        # Map SSLyze result attributes → human-readable TLS version strings
        _CIPHER_RESULT_ATTRS = [
            ("ssl_2_0_cipher_suites", "SSL 2.0"),
            ("ssl_3_0_cipher_suites", "SSL 3.0"),
            ("tls_1_0_cipher_suites", "TLS 1.0"),
            ("tls_1_1_cipher_suites", "TLS 1.1"),
            ("tls_1_2_cipher_suites", "TLS 1.2"),
            ("tls_1_3_cipher_suites", "TLS 1.3"),
        ]

        for server_result in scanner.get_results():
            if server_result.scan_status == ServerScanStatusEnum.ERROR_NO_CONNECTIVITY:
                logger.warning(
                    f"[sslyze] Could not connect to {domain}:{port}: "
                    f"{server_result.connectivity_error_trace}"
                )
                return []

            scan_result = server_result.scan_result
            if not scan_result:
                return []

            for attr_name, tls_ver_label in _CIPHER_RESULT_ATTRS:
                attempt = getattr(scan_result, attr_name, None)
                if attempt is None:
                    continue
                if attempt.status != ScanCommandAttemptStatusEnum.COMPLETED:
                    continue

                cipher_result = attempt.result
                if not cipher_result:
                    continue

                for accepted in cipher_result.accepted_cipher_suites:
                    suite = accepted.cipher_suite
                    cipher_name = suite.name
                    kex = _extract_key_exchange(cipher_name)

                    all_suites.append({
                        "name":         cipher_name,
                        "tls_version":  tls_ver_label,
                        "key_exchange": kex,
                        "key_size":     suite.key_size,
                        "port":         port,
                    })

        logger.info(
            f"[sslyze] {domain}:{port} → {len(all_suites)} accepted cipher suites"
            f"{' (via ' + ip_address + ')' if ip_address else ''}"
        )
        return all_suites

    except Exception as e:
        logger.warning(f"[sslyze] Cipher enumeration failed for {domain}:{port}: {e}")
        return []


def _sslyze_full_scan(
    domain: str,
    port: int = 443,
    starttls: Optional[str] = None,
    ip_address: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Standalone SSLyze scan: extracts certificates AND enumerates cipher suites.
    Used as Priority #2 scanner when testssl.sh fails.

    Returns same structure as run_tls_scan() so it drops in cleanly.
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
        "scan_method": "sslyze",
        "algorithm_source": "sslyze",
    }

    try:
        from sslyze import (
            Scanner,
            ServerScanRequest,
            ServerNetworkLocation,
            ServerNetworkConfiguration,
            ScanCommand,
            ServerScanStatusEnum,
            ScanCommandAttemptStatusEnum,
        )
        from sslyze import ProtocolWithOpportunisticTlsEnum
    except ImportError:
        logger.debug("[sslyze] SSLyze not installed, skipping full scan")
        return result

    try:
        # ── Build server location ──
        location_kwargs = {"hostname": domain, "port": port}
        if ip_address:
            location_kwargs["ip_address"] = ip_address
        server_location = ServerNetworkLocation(**location_kwargs)

        # ── Build network configuration ──
        net_config_kwargs = {
            "tls_server_name_indication": domain,
            "network_timeout": 15,
            "network_max_retries": 2,
        }

        _STARTTLS_MAP = {
            "smtp": ProtocolWithOpportunisticTlsEnum.SMTP,
            "imap": ProtocolWithOpportunisticTlsEnum.IMAP,
            "pop3": ProtocolWithOpportunisticTlsEnum.POP3,
            "ftp":  ProtocolWithOpportunisticTlsEnum.FTP,
        }
        if starttls and starttls.lower() in _STARTTLS_MAP:
            net_config_kwargs["tls_opportunistic_encryption"] = _STARTTLS_MAP[starttls.lower()]

        network_config = ServerNetworkConfiguration(**net_config_kwargs)

        # ── Request cert info + ALL cipher suites ──
        scan_commands = {
            ScanCommand.CERTIFICATE_INFO,
            ScanCommand.SSL_2_0_CIPHER_SUITES,
            ScanCommand.SSL_3_0_CIPHER_SUITES,
            ScanCommand.TLS_1_0_CIPHER_SUITES,
            ScanCommand.TLS_1_1_CIPHER_SUITES,
            ScanCommand.TLS_1_2_CIPHER_SUITES,
            ScanCommand.TLS_1_3_CIPHER_SUITES,
        }

        scan_request = ServerScanRequest(
            server_location=server_location,
            network_configuration=network_config,
            scan_commands=scan_commands,
        )

        scanner = Scanner(
            per_server_concurrent_connections_limit=3,
            concurrent_server_scans_limit=1,
        )
        scanner.queue_scans([scan_request])

        _CIPHER_RESULT_ATTRS = [
            ("ssl_2_0_cipher_suites", "SSL 2.0"),
            ("ssl_3_0_cipher_suites", "SSL 3.0"),
            ("tls_1_0_cipher_suites", "TLS 1.0"),
            ("tls_1_1_cipher_suites", "TLS 1.1"),
            ("tls_1_2_cipher_suites", "TLS 1.2"),
            ("tls_1_3_cipher_suites", "TLS 1.3"),
        ]

        for server_result in scanner.get_results():
            if server_result.scan_status == ServerScanStatusEnum.ERROR_NO_CONNECTIVITY:
                logger.warning(
                    f"[sslyze-full] Could not connect to {domain}:{port}: "
                    f"{server_result.connectivity_error_trace}"
                )
                return result

            scan_result = server_result.scan_result
            if not scan_result:
                return result

            # ── Extract certificate info ──────────────────────────────
            cert_attempt = getattr(scan_result, "certificate_info", None)
            if (
                cert_attempt
                and cert_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED
                and cert_attempt.result
            ):
                cert_info_result = cert_attempt.result
                for deployment in cert_info_result.certificate_deployments:
                    leaf_cert = deployment.received_certificate_chain[0]

                    # Extract algorithm and key size from the leaf cert
                    from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448, dsa

                    pub_key = leaf_cert.public_key()
                    algo = None
                    key_size = None

                    if isinstance(pub_key, rsa.RSAPublicKey):
                        algo = "RSA"
                        key_size = pub_key.key_size
                    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                        algo = "ECDSA"
                        key_size = pub_key.key_size
                    elif isinstance(pub_key, ed25519.Ed25519PublicKey):
                        algo = "Ed25519"
                        key_size = 256
                    elif isinstance(pub_key, ed448.Ed448PublicKey):
                        algo = "Ed448"
                        key_size = 448
                    elif isinstance(pub_key, dsa.DSAPublicKey):
                        algo = "DSA"
                        key_size = pub_key.key_size

                    # Subject
                    from cryptography import x509
                    subject = {}
                    for attr in leaf_cert.subject:
                        if attr.oid._name == "commonName":
                            subject["commonName"] = attr.value
                        elif attr.oid._name == "organizationName":
                            subject["organizationName"] = attr.value

                    # Issuer
                    issuer = {}
                    for attr in leaf_cert.issuer:
                        if attr.oid._name == "commonName":
                            issuer["commonName"] = attr.value
                        elif attr.oid._name == "organizationName":
                            issuer["organizationName"] = attr.value

                    # Expiry
                    not_after = leaf_cert.not_valid_after_utc.strftime("%b %d %H:%M:%S %Y")

                    # Serial
                    serial = format(leaf_cert.serial_number, "x")

                    # SANs
                    sans = []
                    try:
                        san_ext = leaf_cert.extensions.get_extension_for_class(
                            x509.SubjectAlternativeName
                        )
                        sans = san_ext.value.get_values_for_type(x509.DNSName)
                    except x509.ExtensionNotFound:
                        pass

                    result["certificates"].append({
                        "algorithm":      algo,
                        "key_size":       key_size,
                        "subject":        subject,
                        "issuer":         issuer,
                        "notAfter":       not_after,
                        "serialNumber":   serial,
                        "subjectAltName": sans,
                    })

                    logger.info(
                        f"[sslyze-full] {domain}:{port} → algo={algo} key_size={key_size} "
                        f"issuer={issuer.get('organizationName', 'Unknown')}"
                    )
                    break  # Only take first deployment

            # ── Extract cipher suites ─────────────────────────────────
            for attr_name, tls_ver_label in _CIPHER_RESULT_ATTRS:
                attempt = getattr(scan_result, attr_name, None)
                if attempt is None:
                    continue
                if attempt.status != ScanCommandAttemptStatusEnum.COMPLETED:
                    continue

                cipher_result_data = attempt.result
                if not cipher_result_data:
                    continue

                for accepted in cipher_result_data.accepted_cipher_suites:
                    suite = accepted.cipher_suite
                    cipher_name = suite.name
                    kex = _extract_key_exchange(cipher_name)

                    result["cipher_suites"].append({
                        "name":         cipher_name,
                        "tls_version":  tls_ver_label,
                        "key_exchange": kex,
                        "key_size":     suite.key_size,
                        "port":         port,
                    })

                    # Track highest TLS version and first cipher
                    if not result["tls_version"] or "1.3" in tls_ver_label:
                        result["tls_version"] = tls_ver_label
                    if not result["cipher_suite"]:
                        result["cipher_suite"] = cipher_name

                    result["supported_versions"].append(tls_ver_label)

            # Deduplicate supported_versions
            result["supported_versions"] = list(set(result["supported_versions"]))

        logger.info(
            f"[sslyze-full] {domain}:{port} → {len(result['certificates'])} certs, "
            f"{len(result['cipher_suites'])} cipher suites"
        )

    except Exception as e:
        logger.warning(f"[sslyze-full] Full scan failed for {domain}:{port}: {e}", exc_info=True)
        result["error"] = str(e)

    return result


# ─────────────────────────────────────────
# TLS
# ─────────────────────────────────────────

# Ports to try when probing origin IPs for WAF/CDN bypass (kept small for speed)
BYPASS_PORTS = [443]

# Maximum seconds to spend on ALL bypass attempts per origin target
_BYPASS_TIME_BUDGET = 25

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
    "imperva", "incapsula", "zscaler", "tata", "cdn",
    "google", "gws", "ghs"
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
                logger.info(f"[bypass-confirm] REJECTED: domain uses {h} header (still hitting CDN edge)")
                return False
        server = str(response_headers.get("server", "")).lower()
        if any(kw in server for kw in _CDN_SERVER_KEYWORDS):
            logger.info(f"[bypass-confirm] REJECTED: server banner '{server}' matched CDN keyword")
            return False

    # If CT serial is known, confirm we got the same cert
    if ct_serial and cert_serial and ct_serial != cert_serial:
        logger.warning(
            f"[bypass-confirm] REJECTED: cert serial mismatch. got {cert_serial}, CT expects {ct_serial}"
        )
        return False
    
    if response_headers:
        logger.info("[bypass-confirm] SUCCESS: No CDN fingerprints found in response headers.")
    else:
        logger.info("[bypass-confirm] SUCCESS: No headers to check (likely non-HTTP service), assuming bypass.")

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

                # Full cipher enumeration via SSLyze with SNI override (bypass)
                sslyze_suites = _sslyze_cipher_enum(
                    domain=sni_domain, port=port,
                    ip_address=origin_target,
                )
                if sslyze_suites:
                    result["cipher_suites"] = sslyze_suites
                    result["scan_method"] = "origin_bypass+sslyze"
                    logger.info(
                        f"[origin-bypass+sslyze] {sni_domain} via {origin_target}:{port} → "
                        f"{len(sslyze_suites)} cipher suites enumerated"
                    )

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


def run_tls_scan(domain: str, port: int = 443, starttls: Optional[str] = None, ip_address: Optional[str] = None) -> Dict[str, Any]:
    """
    Attempt TLS scan in priority order:
      1. testssl.sh   (most comprehensive — certs + full cipher enum + vulns)
      2. SSLyze       (full cipher enum + cert extraction via cryptography lib)
      3. openssl CLI  (real cert data: algorithm, key_size, issuer, negotiated cipher)
      4. Python ssl   (last resort fallback)

    Falls back to the next method if the current one returns no certificates.
    """
    # ── Priority 1: testssl.sh ────────────────────────────────────────────────
    ALLOWED_TESTSSL_PORTS = {443, 8443, 465, 993, 995, 990}

    if is_tool_available("testssl.sh") and port in ALLOWED_TESTSSL_PORTS:
        logger.info(f"[tls] Trying testssl.sh for {domain}:{port}")
        result = _run_testssl(domain, port, starttls, ip_address)
        if isinstance(result, dict) and result.get("certificates"):
            # If testssl got certs but no ciphers, augment with sslyze
            if not result.get("cipher_suites") and _sslyze_available():
                logger.info(f"[tls] testssl found certs but no ciphers for {domain}:{port}, augmenting with sslyze")
                sslyze_suites = _sslyze_cipher_enum(domain, port, starttls, ip_address)
                if sslyze_suites:
                    result["cipher_suites"] = sslyze_suites
                    result["scan_method"] = "testssl+sslyze"
            return result
        logger.info(f"[tls] testssl returned no certs for {domain}:{port}, falling back")

    # ── Priority 2: SSLyze (standalone — certs + full cipher enum) ────────────
    if _sslyze_available():
        logger.info(f"[tls] Trying SSLyze for {domain}:{port}")
        sslyze_result = _sslyze_full_scan(domain, port, starttls, ip_address)
        if sslyze_result.get("certificates"):
            return sslyze_result
        logger.info(f"[tls] SSLyze returned no certs for {domain}:{port}, falling back")

    # ── Priority 3: OpenSSL CLI ───────────────────────────────────────────────
    if _openssl_available():
        logger.info(f"[tls] Trying openssl CLI for {domain}:{port}")
        result = _openssl_tls_scan(domain, port, starttls, ip_address)
        if result.get("certificates"):
            return result
        logger.info(f"[tls] openssl returned no certs for {domain}:{port}, falling back")

    # ── Priority 4: Python ssl (last resort) ──────────────────────────────────
    logger.info(f"[tls] Using python ssl fallback for {domain}:{port}")
    result = _python_tls_scan(domain, port, ip_address)
    
    # Final check: if we have certs but no ciphers, augment with sslyze
    if result.get("certificates") and not result.get("cipher_suites") and _sslyze_available():
        logger.info(f"[tls] final fallback found certs but no ciphers, augmenting with sslyze")
        sslyze_suites = _sslyze_cipher_enum(domain, port, starttls, ip_address)
        if sslyze_suites:
            result["cipher_suites"] = sslyze_suites
            result["scan_method"] = result.get("scan_method", "") + "+sslyze"
            
    return result



def _openssl_tls_scan(domain: str, port: int = 443, starttls: Optional[str] = None, ip_address: Optional[str] = None) -> Dict[str, Any]:
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
        "algorithm_source": "openssl_cli",
    }

    try:
        # ── Step 1: Get negotiated cipher & TLS version ──
        cipher_info = _get_negotiated_cipher_via_openssl(domain, port, starttls, ip_address)
        result["tls_version"] = cipher_info.get("tls_version")
        result["cipher_suite"] = cipher_info.get("cipher_name")

        if result["cipher_suite"]:
            result["cipher_suites"].append({
                "name":         result["cipher_suite"],
                "tls_version":  result["tls_version"] or "",
                "key_exchange": _extract_key_exchange(result["cipher_suite"]),
                "port":         port,
            })

        # ── Step 2: Get certificate PEM ──
        pem = _get_cert_pem_via_openssl(domain, port, starttls, ip_address)

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
            return _python_tls_scan(domain, port, ip_address)

    except Exception as e:
        logger.error(f"[openssl] TLS scan error for {domain}:{port}: {e}, cascading to python ssl")
        return _python_tls_scan(domain, port, ip_address)

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


def _python_tls_scan(domain: str, port: int = 443, ip_address: Optional[str] = None) -> Dict[str, Any]:
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
        "algorithm_source": "python_ssl",
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

                    # Add to singular-negotiated suite list for UI
                    result["cipher_suites"].append({
                        "name":         cipher_name,
                        "tls_version":  result["tls_version"] or "",
                        "key_exchange": _extract_key_exchange(cipher_name),
                        "port":         port,
                    })

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
    Handles:
      - Certificate fields with <hostCert#N> prefixed IDs
      - cert_signatureAlgorithm (not cert_algorithm)
      - Protocol offering entries (SSLv2, SSLv3, TLS1, TLS1_1, etc.)
      - Cipher suite entries
      - Vulnerability findings (BEAST, BREACH, heartbleed, etc.)
    """
    result = {
        "domain": domain,
        "port": port,
        "tls_version": None,
        "cipher_suite": None,
        "certificates": [],
        "cipher_suites": [],
        "supported_versions": [],
        "vulnerabilities": [],
        "server_banner": None,       # extracted from banner_server
        "error": None,
        "scan_method": "testssl",
        "algorithm_source": "testssl",
    }

    if not isinstance(data, list):
        return result

    # Standard cert fields — we take the first hostCert only
    cert = {
        "algorithm": None,
        "key_size": None,
        "subject": {},
        "issuer": {},
        "notAfter": "",
        "serialNumber": "",
        "subjectAltName": [],
    }

    found_cert = False

    # ---------- Known vulnerability IDs from testssl ----------
    VULN_MAP = {
        "heartbleed":    {"title": "Heartbleed (CVE-2014-0160)",        "cwe": "CWE-119", "severity_not_ok": "CRITICAL"},
        "CCS":           {"title": "CCS Injection (CVE-2014-0224)",     "cwe": "CWE-310", "severity_not_ok": "HIGH"},
        "ticketbleed":   {"title": "Ticketbleed (CVE-2016-9244)",      "cwe": "CWE-200", "severity_not_ok": "HIGH"},
        "ROBOT":         {"title": "ROBOT Attack (CVE-2017-13099)",     "cwe": "CWE-203", "severity_not_ok": "HIGH"},
        "CRIME_TLS":     {"title": "CRIME TLS Compression Attack",     "cwe": "CWE-310", "severity_not_ok": "HIGH"},
        "BREACH":        {"title": "BREACH HTTP Compression Attack",   "cwe": "CWE-310", "severity_not_ok": "MEDIUM"},
        "POODLE_SSL":    {"title": "POODLE SSLv3 (CVE-2014-3566)",     "cwe": "CWE-310", "severity_not_ok": "HIGH"},
        "fallback_SCSV": {"title": "TLS Fallback SCSV Missing",        "cwe": "CWE-757", "severity_not_ok": "MEDIUM"},
        "SWEET32":       {"title": "SWEET32 (CVE-2016-2183)",          "cwe": "CWE-326", "severity_not_ok": "MEDIUM"},
        "FREAK":         {"title": "FREAK Attack (CVE-2015-0204)",     "cwe": "CWE-310", "severity_not_ok": "HIGH"},
        "DROWN":         {"title": "DROWN Attack (CVE-2016-0800)",     "cwe": "CWE-310", "severity_not_ok": "CRITICAL"},
        "LOGJAM":        {"title": "LOGJAM Attack (CVE-2015-4000)",    "cwe": "CWE-310", "severity_not_ok": "HIGH"},
        "BEAST":         {"title": "BEAST Attack (CVE-2011-3389)",     "cwe": "CWE-310", "severity_not_ok": "MEDIUM"},
        "BEAST_CBC_TLS1":{"title": "BEAST CBC TLS 1.0",                "cwe": "CWE-310", "severity_not_ok": "MEDIUM"},
        "LUCKY13":       {"title": "LUCKY13 (CVE-2013-0169)",          "cwe": "CWE-310", "severity_not_ok": "LOW"},
        "winshock":      {"title": "WinShock (CVE-2014-6321)",         "cwe": "CWE-310", "severity_not_ok": "HIGH"},
        "RC4":           {"title": "RC4 Cipher Support (CVE-2013-2566)","cwe": "CWE-326","severity_not_ok": "MEDIUM"},
    }

    # Deprecated protocol IDs
    DEPRECATED_PROTOCOLS = {"SSLv2", "SSLv3", "TLS1", "TLS1_1"}

    for entry in data:
        eid = entry.get("id", "")
        finding = entry.get("finding", "")
        severity = entry.get("severity", "")

        # --- Strip <hostCert#N> prefix for cert field matching ---
        # testssl emits IDs like: "cert_keySize <hostCert#1>"
        base_eid = re.sub(r"\s*<hostCert#\d+>", "", eid).strip()

        # Only process the first host cert (hostCert#1) to avoid duplicates
        if "<hostCert#" in eid and "<hostCert#1>" not in eid:
            continue

        # ── Certificate details ──────────────────────────────────
        if base_eid == "cert_keySize":
            # Finding like: "RSA 2048 bits (exponent is 65537)" or "EC 256 bits"
            m = re.search(r"(\d+)\s*bit", finding)
            if m:
                cert["key_size"] = int(m.group(1))
            # Also extract algo from key size line if present
            algo_m = re.match(r"(RSA|EC|ECDSA|DSA|Ed25519|Ed448)", finding.strip(), re.IGNORECASE)
            if algo_m and not cert["algorithm"]:
                cert["algorithm"] = _normalize_algorithm(algo_m.group(1))
            found_cert = True

        elif base_eid == "cert_signatureAlgorithm":
            # Finding like: "SHA256 with RSA"
            cert["algorithm"] = _normalize_algorithm(finding.strip())
            found_cert = True

        elif base_eid == "cert_algorithm":  # older testssl versions
            if not cert["algorithm"]:
                cert["algorithm"] = _normalize_algorithm(finding.strip())
            found_cert = True

        elif base_eid in ("cert_commonName", "cert_CN"):
            cert["subject"]["commonName"] = finding.strip()
            found_cert = True

        elif base_eid in ("cert_issuer", "cert_caIssuers"):
            # testssl uses cert_caIssuers (e.g. "Sectigo ... CA DV R36 (Sectigo Limited from GB)")
            raw_issuer = finding.strip()
            # Extract org name from parentheses if present: "CA Name (OrgName from Country)"
            org_match = re.search(r'\(([^)]+?)\s+from\s+\w+\)', raw_issuer)
            if org_match:
                cert["issuer"]["organizationName"] = org_match.group(1)
            # Use the part before parentheses as CN
            cn_part = re.sub(r'\s*\([^)]*\)\s*$', '', raw_issuer).strip()
            cert["issuer"]["commonName"] = cn_part if cn_part else raw_issuer
            found_cert = True

        elif base_eid == "cert_notAfter":
            cert["notAfter"] = finding.strip()
            found_cert = True

        elif base_eid in ("cert_serial", "cert_serialNumber"):
            cert["serialNumber"] = finding.strip()
            found_cert = True

        elif base_eid == "cert_subjectAltName":
            # SANs are space-separated
            cert["subjectAltName"] = [s.strip() for s in finding.split() if "." in s]
            found_cert = True

        # ── Protocol offerings ───────────────────────────────────
        elif eid in ("SSLv2", "SSLv3", "TLS1", "TLS1_1", "TLS1_2", "TLS1_3", "protocol_TLS1_3"):
            if "offered" in finding.lower() or eid == "protocol_TLS1_3":
                proto_name = eid.replace("protocol_", "").replace("TLS1_3", "TLS 1.3").replace("TLS1_2", "TLS 1.2") \
                                 .replace("TLS1_1", "TLS 1.1").replace("TLS1", "TLS 1.0") \
                                 .replace("SSLv3", "SSL 3.0").replace("SSLv2", "SSL 2.0")
                result["supported_versions"].append(proto_name)
                # Highest offered becomes primary
                if not result["tls_version"] or "1.3" in proto_name:
                    result["tls_version"] = proto_name

                # Flag deprecated protocols as vulnerability findings
                if eid in DEPRECATED_PROTOCOLS:
                    result["vulnerabilities"].append({
                        "title": f"Deprecated Protocol: {proto_name}",
                        "description": f"Server offers {proto_name} which is deprecated and insecure. {finding}",
                        "severity": "HIGH" if eid in ("SSLv2", "SSLv3") else "MEDIUM",
                        "cwe": "CWE-326",
                        "type": "OUTDATED_TLS",
                    })

        elif eid.startswith("protocol_") and "offered" in finding.lower():
            proto = eid.replace("protocol_", "").replace("_", ".")
            if not result["tls_version"] or "1.3" in proto:
                result["tls_version"] = proto

        # ── Cipher suites ────────────────────────────────────────
        # testssl uses ids like 'cipher-SSLv3', 'cipherorder_TLS1_2', 
        # or sometimes just the protocol name 'TLS1_3' for findings.
        elif eid.startswith("cipher-") or eid.startswith("cipherorder_") or \
             (eid in ("SSLv2", "SSLv3", "TLS1", "TLS1_1", "TLS1_2", "TLS1_3", "protocol_TLS1_3") and \
              any(k in finding for k in ("TLS_", "_WITH_", "0x"))):
            
            cname = finding.strip()
            parts = cname.split()
            if parts:
                for p in reversed(parts):
                    if p.startswith("TLS_") or "_WITH_" in p or ("-" in p and len(p) > 8) or p.startswith("0x"):
                        cname = p
                        break
                else:
                    if len(parts) == 1 and parts[0].lower() not in ("offered", "available", "vulnerable"):
                        cname = parts[0]
                    else:
                        cname = None

            if cname and len(cname) > 3:
                if not any(cs["name"] == cname for cs in result["cipher_suites"]):
                    result["cipher_suites"].append({
                        "name": cname,
                        "tls_version": result["tls_version"] or "Unknown",
                        "key_exchange": _extract_key_exchange(cname),
                        "is_quantum_vulnerable": True,
                        "quantum_risk": 9.0 if "RSA" in cname else 5.0,
                    })
                if not result["cipher_suite"]:
                    result["cipher_suite"] = cname

        # ── Server banner ─────────────────────────────────────────
        elif eid == "banner_server":
            result["server_banner"] = finding.strip()

        # ── Vulnerability findings ───────────────────────────────
        else:
            # Strip any <hostCert#N> prefix for matching
            clean_eid = base_eid
            if clean_eid in VULN_MAP:
                vuln_info = VULN_MAP[clean_eid]
                is_vulnerable = severity not in ("OK", "INFO") or "vulnerable" in finding.lower()
                # Only report if actually vulnerable (not "not vulnerable")
                if "not vulnerable" in finding.lower() or "not offered" in finding.lower():
                    is_vulnerable = False
                if "potentially vulnerable" in finding.lower() or "vulnerable" == finding.lower().split()[0] if finding else False:
                    is_vulnerable = True

                if is_vulnerable:
                    result["vulnerabilities"].append({
                        "title": vuln_info["title"],
                        "description": f"{finding.strip()} (detected by testssl.sh)",
                        "severity": vuln_info["severity_not_ok"],
                        "cwe": vuln_info["cwe"],
                        "type": "OTHER",
                    })

    # Apply defaults for missing cert fields
    if not cert["algorithm"]:
        cert["algorithm"] = "RSA"
    if not cert["key_size"]:
        cert["key_size"] = 2048

    if found_cert:
        result["certificates"].append(cert)

    return result


def _run_testssl(domain: str, port: int = 443, starttls: Optional[str] = None, ip_address: Optional[str] = None) -> Dict[str, Any]:
    # Use a unique filename for this scan to avoid race conditions
    json_path = f"/tmp/testssl_{int(time.time())}.json"
    cmd = ["testssl.sh", "--jsonfile", json_path, "--quiet", "--fast", "-S"]
    if ip_address:
        cmd.extend(["--ip", ip_address])
    
    # Strict timeouts to prevent hanging on bad IPs
    cmd.extend(["--connect-timeout", "3", "--openssl-timeout", "5"])
    
    if starttls:
        cmd.extend(["--starttls", starttls])
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
            print("testssl raw data",raw_data)
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

    result: Dict[str, Any] = {
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
        "network_type": "public",
        "tls_open_ports": [],
    }

    # DNS
    ips = resolve_dns(domain)
    result["resolved_ips"] = ips

    if not ips:
        result["network_type"] = "restricted"  # resolves nowhere
        return result

    target_ip = ips[0]

    # ── Network type detection ────────────────────────────────────────────────
    # Check if ANY resolved IP is private — means this is an internal asset
    # Priority: internal > cdn_protected
    is_internal = any(_is_internal_ip(ip) for ip in ips)
    if is_internal:
        result["network_type"] = "internal"
        logger.info(
            f"[scan] {domain} resolved to private IP(s) {ips} — "
            f"marking as internal network asset"
        )
    # ─────────────────────────────────────────────────────────────────────────

    # CDN
    is_cdn, cdn_provider = _detect_cdn(domain, target_ip)
    result["is_cdn"] = is_cdn
    result["cdn_provider"] = cdn_provider
    if is_cdn and result["network_type"] == "public":
        result["network_type"] = "cdn_protected"

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
    elif 53 in port_numbers:
        result["protocol"] = "DNS"
    else:
        result["protocol"] = "UNKNOWN"

    # Restricted fallback: has public IP but no ports responded
    if (not port_numbers 
            and result["network_type"] == "public" 
            and not is_internal):
        result["network_type"] = "restricted"
        logger.info(f"[scan] {domain}: public IP but no open ports — marking restricted")

    # TLS-capable open ports for bypass
    _TLS_CAPABLE = {443, 8443, 465, 993, 995, 990, 587, 25, 143}
    result["tls_open_ports"] = [
        p["port"] for p in result["open_ports"]
        if p["port"] in _TLS_CAPABLE
    ]

    # ───────────────────────────────────────────────
    # TLS SCAN – run on ALL TLS-capable open ports
    # ───────────────────────────────────────────────
    primary_tls_data = None
    tls_scan_targets = []
    SKIP_TLS_PORTS = {80, 22, 53}

    for port_num in sorted(port_numbers):
        if port_num in TLS_PORTS and port_num not in SKIP_TLS_PORTS:
            tls_scan_targets.append((port_num, TLS_PORTS[port_num].get("starttls")))
        elif port_num not in SKIP_TLS_PORTS and port_num not in TLS_PORTS:
            logger.info(f"[scan] Port {port_num} found open, attempting thorough TLS scan")
            tls_scan_targets.append((port_num, None))

    if not tls_scan_targets and "." in domain and not _IPv4_RE.match(domain):
        if 53 not in port_numbers:  # don't force 443 on pure DNS servers
            logger.info(f"[scan] No TLS ports found for {domain}, forcing 443 probe fallback")
            tls_scan_targets.append((443, None))

    for scan_port, starttls in tls_scan_targets:

        # SSH does not use TLS — skip cert extraction but note the port
        if scan_port == 22:
            logger.info(f"[scan] Skipping TLS cert extraction for SSH port 22 on {domain}")
            continue

        logger.info(f"[scan] TLS scanning {domain}:{scan_port} (starttls={starttls})")

        try:
            tls_data = run_tls_scan(domain, scan_port, starttls, ip_address=target_ip if not result["is_cdn"] else None)
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
    # SERVER SOFTWARE & CDN from TLS scan data
    # ───────────────────────────────────────────────
    # First: extract server banner from testssl if available
    if primary_tls_data and primary_tls_data.get("server_banner"):
        result["server_software"] = primary_tls_data["server_banner"]

    # Second: try HTTP probe (by domain first, then IP)
    if not result["server_software"]:
        headers = _http_probe_cdn_headers(domain, 443, domain)
        if not headers:
            headers = _http_probe_cdn_headers(target_ip, 443, domain)
        if not headers:
            headers = _http_probe_cdn_headers(domain, 80, domain)

        if headers:
            result["server_software"] = headers.get("server")
            if not result["server_software"] and headers.get("x-powered-by"):
                result["server_software"] = f"Powered by {headers.get('x-powered-by')}"

            # Also update CDN detection from these headers if not already detected
            if not result["is_cdn"]:
                for h in headers:
                    if h.lower() in _CDN_FINGERPRINT_HEADERS:
                        result["is_cdn"] = True
                        result["cdn_provider"] = _map_header_to_cdn(h, headers[h])
                        break

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