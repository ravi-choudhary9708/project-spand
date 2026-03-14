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
import asyncio
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
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


# ─── SUBFINDER ──────────────────────────────────────────────────────────────

def run_subfinder(domain: str) -> List[str]:
    """Discover subdomains using Subfinder."""
    if not is_tool_available("subfinder"):
        logger.warning("subfinder not found, using DNS-based fallback")
        return _subfinder_fallback(domain)

    result = run_command(["subfinder", "-d", domain, "-silent", "-timeout", "30"], timeout=60)
    if result["returncode"] == 0 and result["stdout"]:
        subdomains = [s.strip() for s in result["stdout"].split("\n") if s.strip()]
        return subdomains
    return [domain]


def _subfinder_fallback(domain: str) -> List[str]:
    """Fallback: try common subdomains via DNS."""
    common_prefixes = ["www", "mail", "api", "ftp", "smtp", "imap", "vpn", "remote", "secure", "app"]
    discovered = [domain]
    for prefix in common_prefixes:
        subdomain = f"{prefix}.{domain}"
        try:
            socket.gethostbyname(subdomain)
            discovered.append(subdomain)
        except socket.gaierror:
            pass
    return discovered


# ─── DNS RESOLVER ────────────────────────────────────────────────────────────

def resolve_dns(domain: str) -> List[str]:
    """Resolve domain to IP addresses."""
    try:
        results = socket.getaddrinfo(domain, None)
        ips = list(set([r[4][0] for r in results]))
        return ips
    except Exception:
        return []


# ─── NMAP ───────────────────────────────────────────────────────────────────

def run_nmap_scan(target: str) -> Dict[str, Any]:
    """Run Nmap service discovery on target."""
    if not is_tool_available("nmap"):
        logger.warning("nmap not found, using fallback port scan")
        return _nmap_fallback(target)

    # Scan common secure service ports
    ports = "443,8443,25,587,465,143,993,110,995,21,990,22,1194,1723,500"
    result = run_command(
        ["nmap", "-sV", "-p", ports, "--open", "-T4", "--script", "ssl-cert,ssl-enum-ciphers", target],
        timeout=120
    )
    return _parse_nmap_output(result["stdout"], target)


def _nmap_fallback(target: str) -> Dict[str, Any]:
    """Fallback: Simple Python socket-based port check."""
    common_ports = {
        443: "HTTPS", 8443: "HTTPS-ALT", 25: "SMTP", 587: "SUBMISSION",
        465: "SMTPS", 143: "IMAP", 993: "IMAPS", 110: "POP3",
        995: "POP3S", 21: "FTP", 990: "FTPS", 22: "SSH"
    }
    open_ports = []
    for port, service in common_ports.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((target, port))
            sock.close()
            if result == 0:
                open_ports.append({"port": port, "service": service, "state": "open"})
        except Exception:
            pass
    return {"target": target, "open_ports": open_ports, "raw": ""}


def _parse_nmap_output(output: str, target: str) -> Dict[str, Any]:
    """Parse nmap text output into structured data."""
    open_ports = []
    lines = output.split("\n")
    for line in lines:
        if "/tcp" in line and "open" in line:
            parts = line.split()
            if len(parts) >= 3:
                port_proto = parts[0].split("/")
                port = int(port_proto[0]) if port_proto[0].isdigit() else 0
                service = parts[2] if len(parts) > 2 else "unknown"
                open_ports.append({"port": port, "service": service, "state": "open"})
    return {"target": target, "open_ports": open_ports, "raw": output[:2000]}


# ─── TLS SCANNER ─────────────────────────────────────────────────────────────

def run_tls_scan(domain: str, port: int = 443) -> Dict[str, Any]:
    """Scan TLS configuration using Python ssl module (with testssl.sh if available)."""
    if is_tool_available("testssl.sh"):
        return _run_testssl(domain, port)
    return _python_tls_scan(domain, port)


def _python_tls_scan(domain: str, port: int = 443) -> Dict[str, Any]:
    """Native Python TLS inspection using ssl module."""
    result = {
        "domain": domain, "port": port,
        "tls_version": None, "cipher_suite": None,
        "certificates": [], "cipher_suites": [],
        "supported_versions": [], "error": None,
    }
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                result["tls_version"] = ssock.version()
                result["cipher_suite"] = ssock.cipher()[0] if ssock.cipher() else None
                result["supported_versions"].append(ssock.version())

                # Get certificate
                cert = ssock.getpeercert()
                if cert:
                    result["certificates"].append({
                        "subject": dict(x[0] for x in cert.get("subject", [])),
                        "issuer": dict(x[0] for x in cert.get("issuer", [])),
                        "notAfter": cert.get("notAfter", ""),
                        "serialNumber": cert.get("serialNumber", ""),
                        "subjectAltName": [v for _, v in cert.get("subjectAltName", [])],
                    })
    except ssl.SSLError as e:
        result["error"] = f"SSL Error: {str(e)}"
    except ConnectionRefusedError:
        result["error"] = "Connection refused"
    except socket.timeout:
        result["error"] = "Connection timeout"
    except Exception as e:
        result["error"] = str(e)
    return result


def _run_testssl(domain: str, port: int = 443) -> Dict[str, Any]:
    """Run testssl.sh for comprehensive TLS analysis."""
    result = run_command(
        ["testssl.sh", "--jsonfile", "/tmp/testssl_out.json", "--quiet", f"{domain}:{port}"],
        timeout=180
    )
    try:
        with open("/tmp/testssl_out.json") as f:
            return json.load(f)
    except Exception:
        return _python_tls_scan(domain, port)


# ─── MAIN SCANNER ORCHESTRATOR ──────────────────────────────────────────────

def scan_asset(domain: str, progress_callback=None) -> Dict[str, Any]:
    """
    Full scan pipeline for a single asset.
    Returns structured scan data for a domain.
    """
    logger.info(f"Starting scan for: {domain}")
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

    # Step 1: DNS Resolution
    if progress_callback:
        progress_callback(10, "DNS Resolution")
    ips = resolve_dns(domain)
    result["resolved_ips"] = ips

    if not ips:
        result["findings"].append({
            "type": "OTHER",
            "severity": "INFO",
            "title": "Domain Not Resolved",
            "description": f"Could not resolve {domain} to any IP address.",
        })
        return result

    target_ip = ips[0]

    # Step 2: CDN/WAF Detection (basic check by comparing IP with domain)
    if progress_callback:
        progress_callback(20, "CDN/WAF Detection")
    result["is_cdn"] = _detect_cdn(domain, target_ip)

    # Step 3: Port scan
    if progress_callback:
        progress_callback(35, "Service Discovery (Nmap)")
    nmap_data = run_nmap_scan(target_ip if not result["is_cdn"] else domain)
    result["open_ports"] = nmap_data.get("open_ports", [])

    # Step 4: Determine protocol
    ports = [p["port"] for p in result["open_ports"]]
    if 443 in ports or 8443 in ports:
        result["protocol"] = "HTTPS"
    elif 25 in ports or 587 in ports:
        result["protocol"] = "SMTP"
    elif 143 in ports or 993 in ports:
        result["protocol"] = "IMAP"
    elif 22 in ports:
        result["protocol"] = "SSH"
    elif 990 in ports or 21 in ports:
        result["protocol"] = "FTPS"

    # Step 5: TLS scan
    if progress_callback:
        progress_callback(60, "Cryptographic Scanning")

    tls_port = 443
    if result["protocol"] == "SMTP":
        tls_port = 587
    elif result["protocol"] == "IMAP":
        tls_port = 993

    if any(p in ports for p in [443, 8443, 587, 993, 995, 465, 990]):
        tls_data = run_tls_scan(domain, tls_port)
        result["tls_data"] = tls_data
        result["certificates"] = tls_data.get("certificates", [])

        # Extract cipher suite
        if tls_data.get("cipher_suite"):
            result["cipher_suites"].append({
                "name": tls_data["cipher_suite"],
                "tls_version": tls_data.get("tls_version", ""),
                "key_exchange": _extract_key_exchange(tls_data["cipher_suite"]),
            })

    if progress_callback:
        progress_callback(90, "Analysis Complete")

    return result


def _detect_cdn(domain: str, ip: str) -> bool:
    """Basic CDN detection using reverse DNS."""
    cdn_indicators = ["cloudflare", "akamai", "fastly", "cloudfront", "cdn", "edgecast", "incapsula"]
    try:
        hostname = socket.gethostbyaddr(ip)[0].lower()
        return any(cdn in hostname for cdn in cdn_indicators)
    except Exception:
        return False


def _extract_key_exchange(cipher_name: str) -> str:
    """Extract key exchange algorithm from cipher suite name."""
    name_upper = cipher_name.upper()
    if "ECDHE" in name_upper:
        return "ECDHE"
    elif "DHE" in name_upper:
        return "DHE"
    elif "RSA" in name_upper:
        return "RSA"
    elif "ECDH" in name_upper:
        return "ECDH"
    return "UNKNOWN"
