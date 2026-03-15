"""
Scanning Engine - Main orchestrator
Wraps Nmap, TestSSL, SSLyze, and Subfinder with a smart fallback to
simulation mode for environments where tools are unavailable.
"""
import subprocess
import json
import os
import socket
import ssl
from datetime import datetime, timedelta
from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)


def run_command(cmd: List[str], timeout: int = 60) -> Dict[str, Any]:
    """Run a shell command and return stdout/stderr."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
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
        22: "SSH"
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
# TLS
# ─────────────────────────────────────────

def run_tls_scan(domain: str, port: int = 443):

    if is_tool_available("testssl.sh"):
        return _run_testssl(domain, port)

    return _python_tls_scan(domain, port)


def _python_tls_scan(domain: str, port: int = 443):

    result = {
        "domain": domain,
        "port": port,
        "tls_version": None,
        "cipher_suite": None,
        "certificates": [],
        "cipher_suites": [],
        "supported_versions": [],
        "error": None
    }

    try:

        context = ssl.create_default_context()

        with socket.create_connection((domain, port), timeout=10) as sock:

            with context.wrap_socket(sock, server_hostname=domain) as ssock:

                result["tls_version"] = ssock.version()

                cipher = ssock.cipher()

                if cipher:
                    result["cipher_suite"] = cipher[0]

                cert = ssock.getpeercert()

                if cert:

                    result["certificates"].append({

                        "subject": dict(x[0] for x in cert.get("subject", [])),
                        "issuer": dict(x[0] for x in cert.get("issuer", [])),
                        "notAfter": cert.get("notAfter", ""),
                        "serialNumber": cert.get("serialNumber", ""),
                        "subjectAltName": [v for _, v in cert.get("subjectAltName", [])],
                    })

    except Exception as e:
        result["error"] = str(e)

    return result


def _run_testssl(domain: str, port: int = 443):

    run_command(
        ["testssl.sh", "--jsonfile", "/tmp/testssl.json", "--quiet", f"{domain}:{port}"],
        timeout=180
    )

    try:
        with open("/tmp/testssl.json") as f:
            return json.load(f)
    except Exception:
        return _python_tls_scan(domain, port)


# ─────────────────────────────────────────
# MAIN SCAN
# ─────────────────────────────────────────

def scan_asset(domain: str, progress_callback=None):

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
        "findings": []
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
    # IMPROVED PROTOCOL DETECTION
    # ───────────────

    ports = [p["port"] for p in result["open_ports"]]
    port_numbers = set(ports)

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

    # TLS
    if 443 in port_numbers:

        tls_data = run_tls_scan(domain, 443)

        result["tls_data"] = tls_data
        result["certificates"] = tls_data.get("certificates", [])

        if tls_data.get("cipher_suite"):

            result["cipher_suites"].append({

                "name": tls_data["cipher_suite"],
                "tls_version": tls_data.get("tls_version", ""),
                "key_exchange": _extract_key_exchange(tls_data["cipher_suite"])

            })

    return result


# ─────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────

def _detect_cdn(domain: str, ip: str):

    cdn_keywords = ["cloudflare", "akamai", "fastly", "cloudfront", "cdn"]

    try:

        hostname = socket.gethostbyaddr(ip)[0].lower()

        return any(k in hostname for k in cdn_keywords)

    except Exception:
        return False


def _extract_key_exchange(cipher_name: str):

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