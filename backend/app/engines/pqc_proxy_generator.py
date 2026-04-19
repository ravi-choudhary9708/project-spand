"""
PQC Proxy Config Generator — QuantumShield

Generates deployable Docker + Nginx configs that wrap legacy servers
in a Quantum-Safe TLS termination proxy using OQS (Open Quantum Safe).

Architecture:
  Internet → [PQC Proxy (ML-KEM/Kyber)] → [Legacy Server (RSA/ECDSA)]
"""

import io
import zipfile
import textwrap
from datetime import datetime

# ─── PQC Algorithm Mapping ───────────────────────────────────────────────────
# Maps detected classical algorithms to their PQC replacement recommendations

PQC_KEM_MAP = {
    "RSA":     {"kem": "kyber768",     "sig": "dilithium3",  "nist": "ML-KEM-768 (FIPS 203)"},
    "ECDSA":   {"kem": "kyber768",     "sig": "dilithium3",  "nist": "ML-DSA-65 (FIPS 204)"},
    "ECC":     {"kem": "kyber768",     "sig": "dilithium3",  "nist": "ML-DSA-65 (FIPS 204)"},
    "ECDHE":   {"kem": "kyber1024",    "sig": "dilithium5",  "nist": "ML-KEM-1024 (FIPS 203)"},
    "DHE":     {"kem": "kyber768",     "sig": "dilithium3",  "nist": "ML-KEM-768 (FIPS 203)"},
    "DSA":     {"kem": "kyber768",     "sig": "falcon512",   "nist": "FALCON-512 (FIPS 206)"},
    "DH":      {"kem": "kyber768",     "sig": "dilithium3",  "nist": "ML-KEM-768 (FIPS 203)"},
}

DEFAULT_PQC = {"kem": "kyber768", "sig": "dilithium3", "nist": "ML-KEM-768 (FIPS 203)"}


def _get_pqc_config(algorithm: str) -> dict:
    """Resolve the PQC algorithm config based on detected classical algo."""
    if not algorithm:
        return DEFAULT_PQC
    algo_upper = algorithm.upper()
    for key, value in PQC_KEM_MAP.items():
        if key in algo_upper:
            return value
    return DEFAULT_PQC


def generate_docker_compose(domain: str, pqc: dict, backend_port: int = 8080) -> str:
    """Generate a docker-compose.yml for the PQC sidecar proxy."""
    return textwrap.dedent(f"""\
        # ──────────────────────────────────────────────────────────
        # QuantumShield PQC Sidecar Proxy
        # Target: {domain}
        # PQC KEM: {pqc['kem']} | PQC Signature: {pqc['sig']}
        # Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}
        # ──────────────────────────────────────────────────────────
        
        version: '3.8'
        
        services:
          pqc-proxy:
            image: openquantumsafe/nginx:latest
            container_name: pqc_proxy_{domain.replace('.', '_')}
            restart: unless-stopped
            ports:
              - "443:443"
              - "80:80"
            volumes:
              - ./nginx-pqc.conf:/etc/nginx/nginx.conf:ro
              - ./certs:/etc/nginx/certs:ro
            environment:
              - KEM_ALG={pqc['kem']}
              - SIG_ALG={pqc['sig']}
            networks:
              - pqc-bridge
            depends_on:
              - legacy-backend
            healthcheck:
              test: ["CMD", "curl", "-f", "http://localhost/health"]
              interval: 30s
              timeout: 5s
              retries: 3
        
          legacy-backend:
            # ⚠️ REPLACE THIS with your actual legacy server configuration.
            # Option A: Point to your existing server via network
            # Option B: Use 'network_mode: host' and proxy_pass to localhost
            image: nginx:alpine
            container_name: legacy_{domain.replace('.', '_')}
            ports:
              - "{backend_port}:80"
            networks:
              - pqc-bridge
        
        networks:
          pqc-bridge:
            driver: bridge
            name: pqc_bridge_{domain.replace('.', '_')}
    """)


def generate_nginx_conf(domain: str, pqc: dict, backend_port: int = 8080) -> str:
    """Generate an nginx config with PQC TLS termination."""
    return textwrap.dedent(f"""\
        # ──────────────────────────────────────────────────────────
        # QuantumShield PQC Nginx Configuration
        # Domain: {domain}
        # Algorithm: {pqc['sig']} (signature) + {pqc['kem']} (key exchange)
        # NIST Standard: {pqc['nist']}
        # ──────────────────────────────────────────────────────────
        
        worker_processes auto;
        error_log /var/log/nginx/error.log warn;
        pid /var/run/nginx.pid;
        
        events {{
            worker_connections 1024;
        }}
        
        http {{
            include /etc/nginx/mime.types;
            default_type application/octet-stream;
        
            # Logging
            log_format pqc '$remote_addr - $remote_user [$time_local] '
                           '"$request" $status $body_bytes_sent '
                           '"$http_referer" "$http_user_agent" '
                           'PQC=$http_x_pqc_protected';
        
            access_log /var/log/nginx/access.log pqc;
        
            # Performance
            sendfile on;
            tcp_nopush on;
            keepalive_timeout 65;
            gzip on;
        
            # ── PQC TLS Termination ──────────────────────────────
            server {{
                listen 443 ssl;
                listen [::]:443 ssl;
                server_name {domain};
        
                # PQC Certificate (generated by OQS OpenSSL)
                ssl_certificate     /etc/nginx/certs/pqc-server.crt;
                ssl_certificate_key /etc/nginx/certs/pqc-server.key;
        
                # Enforce TLS 1.3 only (required for PQC key exchange)
                ssl_protocols TLSv1.3;
                ssl_prefer_server_ciphers off;
        
                # Security headers
                add_header X-PQC-Protected "true" always;
                add_header X-PQC-Algorithm "{pqc['kem']}" always;
                add_header X-Frame-Options "SAMEORIGIN" always;
                add_header X-Content-Type-Options "nosniff" always;
                add_header Strict-Transport-Security "max-age=63072000" always;
        
                # Health check endpoint
                location /health {{
                    return 200 '{{"status":"healthy","pqc":true,"kem":"{pqc['kem']}","sig":"{pqc['sig']}"}}';
                    add_header Content-Type application/json;
                }}
        
                # Reverse proxy to legacy backend
                location / {{
                    proxy_pass http://legacy-backend:80;
                    proxy_http_version 1.1;
                    proxy_set_header Host $host;
                    proxy_set_header X-Real-IP $remote_addr;
                    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                    proxy_set_header X-Forwarded-Proto $scheme;
                    proxy_set_header X-PQC-Protected "true";
                    proxy_set_header X-PQC-KEM "{pqc['kem']}";
        
                    # Timeouts
                    proxy_connect_timeout 30s;
                    proxy_read_timeout 120s;
                    proxy_send_timeout 120s;
                }}
            }}
        
            # ── HTTP → HTTPS Redirect ────────────────────────────
            server {{
                listen 80;
                listen [::]:80;
                server_name {domain};
                return 301 https://$server_name$request_uri;
            }}
        }}
    """)


def generate_cert_script(domain: str, pqc: dict) -> str:
    """Generate a shell script to create PQC certificates using OQS OpenSSL."""
    return textwrap.dedent(f"""\
        #!/bin/bash
        # ──────────────────────────────────────────────────────────
        # QuantumShield PQC Certificate Generator
        # Uses Open Quantum Safe (OQS) OpenSSL provider
        # Domain: {domain}
        # Signature Algorithm: {pqc['sig']}
        # ──────────────────────────────────────────────────────────
        
        set -e
        
        CERT_DIR="./certs"
        mkdir -p "$CERT_DIR"
        
        echo "🔐 Generating PQC certificate for {domain}..."
        echo "   Algorithm: {pqc['sig']}"
        echo "   NIST Standard: {pqc['nist']}"
        echo ""
        
        # ── Option 1: Using OQS OpenSSL Provider (Recommended) ──
        # Install: https://github.com/open-quantum-safe/oqs-provider
        #
        # openssl req -x509 -new -newkey {pqc['sig']} \\
        #   -keyout "$CERT_DIR/pqc-server.key" \\
        #   -out "$CERT_DIR/pqc-server.crt" \\
        #   -nodes -days 365 \\
        #   -subj "/CN={domain}/O=QuantumShield PQC Proxy" \\
        #   -provider oqsprovider -provider default
        
        # ── Option 2: Using OQS Docker Image (Easiest) ──────────
        docker run --rm -v "$(pwd)/certs:/certs" \\
          openquantumsafe/curl:latest \\
          sh -c "openssl req -x509 -new -newkey {pqc['sig']} \\
            -keyout /certs/pqc-server.key \\
            -out /certs/pqc-server.crt \\
            -nodes -days 365 \\
            -subj '/CN={domain}/O=QuantumShield PQC Proxy' \\
            -provider oqsprovider -provider default"
        
        # ── Option 3: Self-signed classical cert (for testing) ───
        # Uncomment below if you just want to test the proxy setup:
        #
        # openssl req -x509 -newkey rsa:4096 \\
        #   -keyout "$CERT_DIR/pqc-server.key" \\
        #   -out "$CERT_DIR/pqc-server.crt" \\
        #   -nodes -days 365 \\
        #   -subj "/CN={domain}/O=QuantumShield Proxy (Classical)"
        
        echo ""
        echo "✅ PQC certificate generated!"
        echo "   Certificate: $CERT_DIR/pqc-server.crt"
        echo "   Private Key: $CERT_DIR/pqc-server.key"
        echo ""
        echo "Next steps:"
        echo "  1. docker-compose up -d"
        echo "  2. curl -k https://{domain} (test PQC handshake)"
    """)


def generate_readme(domain: str, algorithm: str, key_size: int, hndl_score: float, pqc: dict) -> str:
    """Generate a README.md for the proxy deployment package."""
    return textwrap.dedent(f"""\
        # 🛡️ QuantumShield PQC Sidecar Proxy
        
        ## Target: `{domain}`
        
        This package contains a ready-to-deploy **Post-Quantum Cryptographic (PQC) proxy**
        that wraps your legacy server in quantum-safe TLS termination.
        
        ### Detected Vulnerability
        | Field | Value |
        |-------|-------|
        | Domain | `{domain}` |
        | Current Algorithm | **{algorithm or 'Unknown'}** |
        | Key Size | **{key_size or 'Unknown'}-bit** |
        | HNDL Risk Score | **{hndl_score:.1f}/10** |
        | Status | ⚠️ Quantum Vulnerable |
        
        ### PQC Replacement
        | Field | Value |
        |-------|-------|
        | Key Exchange | **{pqc['kem']}** (ML-KEM / Kyber) |
        | Signature | **{pqc['sig']}** (ML-DSA / Dilithium) |
        | NIST Standard | **{pqc['nist']}** |
        | Post-Deployment HNDL | **~0.5/10** (Quantum Safe ✅) |
        
        ---
        
        ## 🚀 Quick Start
        
        ```bash
        # 1. Generate PQC certificate
        chmod +x generate-pqc-cert.sh
        ./generate-pqc-cert.sh
        
        # 2. Start the PQC proxy
        docker-compose up -d
        
        # 3. Test the PQC handshake
        curl -k https://{domain}
        ```
        
        ## Architecture
        
        ```
        Internet (Quantum Attacker)
              │
              ▼
        ┌─────────────────────┐
        │  PQC Sidecar Proxy  │  Port 443
        │  TLS 1.3 + {pqc['kem']}   │  ← Quantum Safe
        └──────────┬──────────┘
                   │ HTTP (internal)
        ┌──────────▼──────────┐
        │   Legacy Server     │  Port 80/8080
        │   {algorithm or 'RSA'}-{key_size or '2048'}           │  ← Untouched
        └─────────────────────┘
        ```
        
        ## ⚠️ Important Notes
        
        1. **Replace `legacy-backend`** in `docker-compose.yml` with your actual server configuration.
        2. **Certificate**: The generated PQC cert is self-signed. For production, use your organization's CA with PQC support.
        3. **Testing**: Use `openquantumsafe/curl` to verify the PQC handshake: 
           ```
           docker run --rm openquantumsafe/curl curl -k https://{domain}
           ```
        
        ---
        
        *Generated by QuantumShield — Post-Quantum Cryptographic Assessment Platform*  
        *{datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}*
    """)


def generate_proxy_config_zip(
    domain: str,
    algorithm: str = None,
    key_size: int = None,
    hndl_score: float = 0.0,
    open_ports: list = None,
) -> bytes:
    """
    Generate a complete PQC proxy deployment package as a ZIP file.
    
    Returns bytes of the ZIP archive containing:
    - docker-compose.yml
    - nginx-pqc.conf
    - generate-pqc-cert.sh
    - README.md
    """
    pqc = _get_pqc_config(algorithm)
    backend_port = 8080

    # Try to detect backend port from scan data
    if open_ports:
        https_ports = [p.get("port") for p in open_ports if p.get("port") in (443, 8443)]
        http_ports = [p.get("port") for p in open_ports if p.get("port") in (80, 8080, 8000)]
        if http_ports:
            backend_port = http_ports[0]

    # Generate all config files
    compose = generate_docker_compose(domain, pqc, backend_port)
    nginx = generate_nginx_conf(domain, pqc, backend_port)
    cert_script = generate_cert_script(domain, pqc)
    readme = generate_readme(domain, algorithm, key_size, hndl_score, pqc)

    # Package into ZIP
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        folder = f"pqc-proxy-{domain.replace('.', '-')}"
        zf.writestr(f"{folder}/docker-compose.yml", compose)
        zf.writestr(f"{folder}/nginx-pqc.conf", nginx)
        zf.writestr(f"{folder}/generate-pqc-cert.sh", cert_script)
        zf.writestr(f"{folder}/README.md", readme)
        zf.writestr(f"{folder}/certs/.gitkeep", "")

    buffer.seek(0)
    return buffer.getvalue()
