#  QuantumShield — Quantum-Proof Systems Scanner

**Team Spand | GEC Madhubani**

> A tool that scans public-facing infrastructure for quantum cryptography vulnerabilities, generates CycloneDX CBOM reports, and maps findings to NIST PQC, RBI, and CERT-In compliance frameworks.

---

##  Quick Start

```bash
# Clone the repo
git clone git@github.com:ravi-choudhary9708/project-spand.git
cd project-spand

# Start everything with one command
docker-compose up -d --build

# Wait 1-2 minutes, then open
http://localhost
```

**Default login credentials:**

| Role | Username | Password |
|------|----------|----------|
| Admin | `admin` | `admin123` |
| Security Analyst | `analyst` | `analyst123` |
| Compliance Officer | `compliance` | `comply123` |
| SOC Team | `soc` | `soc123` |
| Management | `manager` | `manager123` |

---

##  Documentation & Deep Dives

For a comprehensive understanding of the system's internals, science, and compliance logic, refer to our detailed documentation suite in the [`docs/`](./docs/) directory:

- [**01 Architecture**](./docs/01_ARCHITECTURE.md): Technical stack, container orchestration, and parallel scan engine.
- [**02 Scanning Pipeline**](./docs/02_SCANNING_PIPELINE.md): Pre-flight discovery, origin bypass, and the Path A/B/C decision matrix.
- [**03 Network Intelligence**](./docs/03_NETWORK_INTELLIGENCE.md): Asset classification logic and automated internal data leak detection.
- [**04 HNDL Science**](./docs/04_HNDL_SCORING_SCIENCE.md): The mathematical formula and per-algorithm risk weights for Harvest-Now-Decrypt-Later.
- [**05 Compliance Enforcement**](./docs/05_COMPLIANCE_ENFORCEMENT.md): Mapping findings to NIST FIPS 203/204/205, RBI, and CERT-In.
- [**06 Data & CBOM**](./docs/06_DATA_SCHEMA_HANDBOOK.md): Database schema overview and the state-of-the-art CycloneDX CBOM generator.
- [**07 Developer Onboarding**](./docs/07_DEVELOPER_ONBOARDING.md): Code structure guide, RBAC security model, and contribution workflow.
- [**08 AI Remediation Engine**](./docs/08_AI_REMEDIATION_ENGINE.md): Deep architectural dives and engineer-ready migration blueprints via dual-engine AI.

---

##  What It Does

QuantumShield scans your organization's public-facing domains and tells you:

1. **Which assets are vulnerable to quantum attacks** (RSA, ECC, Diffie-Hellman)
2. **How urgent the risk is** via HNDL (Harvest-Now-Decrypt-Later) score 0–10
3. **Which compliance frameworks you are violating** (NIST FIPS 203/204/205, RBI, CERT-In)
4. **Exactly what to do to fix it** via step-by-step remediation playbooks
5. **A complete Cryptographic Bill of Materials (CBOM)** in CycloneDX 1.4 format

---

##  Key Features

| Feature | Description |
|---------|-------------|
| **Asset Discovery** | Subfinder (strictly bounded) — discovers public subdomains only |
| **Network Classification** | 4-tier model: `public`, `internal`, `cdn_protected`, `restricted` |
| **HNDL Scoring** | Context-aware formula: BCS × Sensitivity × Shelf Life × PFS × TLS Version |
| **CycloneDX CBOM** | Industry-standard Cryptographic Bill of Materials, exportable as JSON or XML |
| **Compliance Mapping** | Automatic mapping to NIST FIPS 203/204/205, NIST IR 8547, RBI, CERT-In |
| **Parallel Engine** | Hybrid architecture: 4 Celery workers × 5 Parallel Threads per scan |
| **RBAC Dashboard** | 5 user roles — Admin, Analyst, Compliance, SOC, Management |
| **CDN Detection** | Detects Cloudflare, Akamai, Fastly and attempts origin bypass via IP/SPF |
| **Infra Node Graph** | Interactive network topology map with force-directed physics and HNDL heatmaps |
| **Full Org / Custom URL** | Scan an entire organization or a single specific URL |
| **AI Remediation** | Dynamic migration playbooks via Qwen 2.5 and Llama 3.1 with dual-engine fallback |

---

## 🌐 Scan Modes

### Full Organization Scan (Default)

By default, the **"Full Organization Scan"** checkbox is checked. When you enter a domain like `pnb.in`, the scanner will:
- Discover **all subdomains** via subfinder (`netbanking.pnb.bank.in`, `creditcard.pnb.bank.in`, etc.)
- Scan every discovered subdomain for quantum vulnerabilities
- Build a complete picture of your organization's cryptographic posture

### Custom URL Scan

> ** To scan only a specific URL, uncheck the "Full Organization Scan" checkbox.**

When unchecked, the scanner will **only scan the exact URL you provide** — no subdomain discovery. This is useful when:
- You want to scan a single service like `aws.amazon.com`
- You're testing a specific endpoint
- You want faster results for a single target

---

## 🕸️ Infrastructure Visualizer (Node Graph)

QuantumShield includes a state-of-the-art **Interactive Topology Map** that visualizes your organization's cryptographic infrastructure using advanced force-directed physics.

### Key Visual Features:
- **Hierarchical Gravity**: Unlike standard graphs that collapse into a "gravity well," QuantumShield uses distinct force groups (Org: -800, Domain: -200, IP: -80, Port: -30) to ensure clean spacing and clear hierarchy.
- **HNDL Heatmap**: Domain nodes are color-coded in real-time based on their risk (Green → Orange → Red).
- **Network Awareness**: Internal IPs (RFC 1918) glow red, while CDN-protected nodes are highlighted with purple rings.
- **Three Layout Modes**:
    - **Force-directed**: Organic, physics-based movement.
    - **Radial Tiers**: Concentric rings showing logical distance from the core.
    - **Cluster**: Grouped by asset type into optimized quadrants.
- **Deep Interactivity**: Link distance sliders, type-based filtering, and pin-to-drag node manipulation.

---

##  How the Scan Works — Complete Pipeline

When you click "Start Scan" and enter a domain:

### Step 1: Input Cleaning
The target URL is stripped of `http://`, `https://`, paths, and trailing slashes to get a bare domain.

### Step 2: Subdomain Discovery (Full Org Scan only)
**Subfinder** discovers all public subdomains using various passive sources. To maintain a strict scan perimeter, the scanner **only** targets domains found by subfinder and does not automatically expand the scope using broad CT log scrapes.

### Step 3: Intelligence Gathering (DNS, SPF, CT)
The scanner gathers metadata and origin bypass targets from multiple sources:
- **CT Log Cache**: Certificate Transparency logs are queried from [crt.sh](https://crt.sh). Hostnames are stripped to maintain scope, but **IP addresses** are extracted as high-confidence bypass targets.
- **SPF Mining**: Authoritative DNS TXT records are mined for `ip4:` and `include:` directives to find origin IPs.
- **Passive DNS**: Historical IP resolution data from ViewDNS.info is used to find IPs active before CDN deployment.

### Step 4: Per-Domain Scanning

For each domain, the scanner runs through this pipeline:

#### 4a. DNS Resolution
Resolves the domain to IP addresses using `socket.getaddrinfo()`.

#### 4b. CDN Detection
Checks if the IP belongs to Cloudflare, Akamai, Fastly, or other CDN providers by reverse-DNS lookup.

#### 4c. Port Scan (Optimized)
Scans only security-relevant ports:
```
443, 8443 (HTTPS), 25, 587, 465 (SMTP), 143, 993 (IMAP), 110, 995 (POP3), 
21, 990 (FTPS), 22 (SSH), 53 (DNS), 1194, 1723, 500 (VPN)
```
- **Nmap**: Fast SYN scan (`-sS -T4`) — completes in ~5 seconds.
- **Fallback**: Concurrent socket checks via ThreadPoolExecutor — ports checked simultaneously.

#### 4d. Network Classification & Asset Proximity
The scanner automatically classifies each asset using an IP-based analysis:
- **`internal`**: IP belongs to RFC 1918/4193 private ranges.
- **`cdn_protected`**: IP belongs to Cloudflare, Akamai, or Fastly ranges.
- **`restricted`**: Port scan yielded no response (Firewalled / CDN-only).
- **`public`**: Standard internet-reachable infrastructure.

> [!IMPORTANT]
> **Data Leak Detection (CWE-200)**: Assets found resolving to `internal` IPs are automatically flagged with a medium-severity finding, as their presence in public CT logs exposes internal network topology.

#### 4e. TLS Certificate Extraction — Three-Method Cascade

The scanner tries **three methods** in order, falling back to the next if no certificate is returned:

| Priority | Method | Data Quality | When It's Used |
|----------|--------|--------------|----------------|
| 1 | **TestSSL.sh** | Best | When installed (Docker has it) |
| 2 | **OpenSSL CLI** | Real | Direct TLS handshake + cert parsing |
| 3 | **Python SSL + cryptography** | Real | Fallback — parses DER cert for real algo/key_size |

**Key:** Each method extracts the **real** algorithm (RSA, ECDSA, Ed25519), key size, issuer, expiry, SANs, and cipher suite from the actual TLS certificate.

### Step 5: Three-Path Algorithm Decision

The scanner uses a priority-based path system to determine the certificate algorithm:

```
PATH A  (BEST)  — TLS direct scan succeeded
                   → Real leaf certificate data from openssl/python ssl
                   → Algorithm, key size, issuer, expiry all REAL

PATH B1 (GOOD)  — TLS blocked (CDN/WAF)
                   → CT SAN origin-IP bypass → connect to origin IP with SNI
                   → Real leaf certificate data (bypasses CDN)
                   → Sources: CT SANs, SPF records, passive DNS history

PATH B2 (APPROX) — No origin IP found
                   → CT log cache provides algorithm from issuer name
                   → Algorithm is APPROXIMATE (issuer-inferred, not leaf cert)

PATH C  (DEFAULT) — No data anywhere
                   → Conservative RSA-2048 default assumption
```

### Step 6: HNDL Risk Scoring
Calculates the Harvest-Now-Decrypt-Later risk score (see formula below).

### Step 7: Compliance Mapping
Maps each finding to NIST FIPS 203/204/205, NIST IR 8547, RBI, and CERT-In controls.

### Step 8: Remediation Generation
Generates step-by-step migration playbooks (e.g., RSA-2048 → ML-KEM-768).

### Step 9: CBOM Generation
Creates a CycloneDX 1.4 JSON Cryptographic Bill of Materials with all findings.

---

##  HNDL Risk Score Formula (v2)

```text
HNDL_final = min(10.0, BCS × W_sensitivity × M_shelf × M_pfs × M_tls_version)
```

### Base Cryptographic Score (BCS)
```text
BCS = (AlgoVuln × 0.50) + (KeySizeRisk × 0.20) + (TLSRisk × 0.20) + (ExpiryRisk × 0.10)
```

### Algorithm Vulnerability Scores

| Algorithm | Score | Quantum Risk |
|-----------|-------|-------------|
| RSA-1024 | 10.0 | 🔴 Critical |
| RSA-2048 | 9.0 | 🔴 Critical |
| RSA-4096 | 7.5 | 🟠 High |
| ECDSA / ECC | 9.0 | 🔴 Critical |
| ECDHE | 8.5 | 🔴 Critical |
| DHE | 8.0 | 🟠 High |
| AES-128 | 3.0 | 🟡 Medium |
| AES-256 | 1.0 | 🟢 Safe |
| ML-KEM / ML-DSA / FALCON / SPHINCS+ | 0.5 | 🟢 PQC Safe |

### TLS Version Risk Scores

| TLS Version | Score | Risk |
|-------------|-------|------|
| SSLv2 / SSLv3 | 10.0 | 🔴 Critical (deprecated) |
| TLS 1.0 | 9.0 | 🔴 Critical (deprecated) |
| TLS 1.1 | 8.0 | 🟠 High (deprecated) |
| TLS 1.2 | 4.0 | 🟡 Medium (still acceptable) |
| TLS 1.3 | 1.0 | 🟢 Safe (current standard) |

### Data Sensitivity (Auto-inferred from domain)

| Domain Pattern | Sensitivity | Example |
|---------------|-------------|---------|
| `netbanking.*`, `payment.*`, `pay.*` | 10.0 | Banking/payment portals |
| `swift.*`, `cbdc.*`, `rtgs.*` | 9.5 | Financial infrastructure |
| `vpn.*`, `auth.*`, `login.*` | 9.0 | Authentication systems |
| `creditcard.*`, `loan.*` | 8.5 | Credit/lending services |
| `api.*`, `gateway.*`, `upi.*` | 7.5 | API gateways |
| `mail.*`, `smtp.*` | 6.0 | Email systems |
| `www.*`, `web.*` | 5.0 | Web properties |
| `cdn.*`, `static.*`, `assets.*` | 2.0 | Static content |

### Risk Labels

| Score Range | Label | Meaning |
|-------------|-------|---------|
| 0.0 – 3.0 | 🟢 Quantum Safe | Using PQC-ready algorithms |
| 3.1 – 5.5 | 🟡 Partially Safe | Some quantum risk, hybrid OK |
| 5.6 – 7.8 | 🟠 Vulnerable | Needs migration planning |
| 7.9 – 10.0 | 🔴 Critical Risk | Immediate action required |

---

##  Architecture

```
Browser (React JS)
    ↓
Nginx (reverse proxy)
    ↓
FastAPI Backend (Python)
    ↓
Celery Worker (async scan)
    ↓ ↓ ↓ ↓ ↓ ↓
subfinder  nmap  TLS  HNDL  CBOM  Compliance
    ↓
PostgreSQL (results)
Redis (task queue)
```

### High-Performance Parallel Execution
QuantumShield is engineered for enterprise-scale throughput:
- **Macro-Level Parallelism**: 4 concurrent Celery worker processes (one per organization or large-scale scan).
- **Micro-Level Parallelism**: Thread Pool (5 workers) per domain-analysis task.
- **Efficiency**: Allows for **20 concurrent domain scans** across the system, ensuring high-speed analysis even for domains with long-tail TLS handshakes.

### Tech Stack

**Backend:** Python 3.11, FastAPI, SQLAlchemy, PostgreSQL, Celery, Redis

**Frontend:** React 18, Vite, Recharts, Axios

**Scanning Tools:** Nmap, TestSSL, SSLyze, Subfinder, OpenSSL, Python `cryptography`

**Infrastructure:** Docker Compose, Nginx

---

##  Project Structure

```
project-spand/
├── docker-compose.yml          # Starts all 6 containers
├── .env                        # Environment variables
├── crt.txt                     # Local CT log cache (warm cache for crt.sh)
├── nginx/
│   └── nginx.conf              # Reverse proxy config
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── app/
│       ├── main.py             # FastAPI app + user seeding
│       ├── config.py           # Environment settings
│       ├── database.py         # PostgreSQL connection
│       ├── celery_app.py       # Celery + Redis config
│       ├── auth/
│       │   └── auth.py         # JWT + bcrypt + RBAC
│       ├── models/
│       │   └── models.py       # 9 database tables
│       ├── routers/
│       │   ├── auth_router.py      # POST /login, GET /me
│       │   ├── scans_router.py     # POST /scans, GET /scans/{id}/cbom
│       │   ├── dashboard_router.py # GET /dashboard — all stats
│       │   └── assets_router.py    # GET /assets — filterable inventory
│       ├── scanning/
│       │   ├── scanner.py          # Port scan, TLS cert extraction, CDN bypass
│       │   └── ct_log_scanner.py   # CT log queries, origin IP discovery
│       ├── tasks/
│       │   └── scan_tasks.py       # Full scan pipeline (PATH A/B/C)
│       └── engines/
│           ├── hndl_engine.py          # HNDL risk formula (5-factor)
│           ├── cbom_generator.py       # CycloneDX 1.4 output
│           ├── compliance_engine.py    # NIST/RBI/CERT-In mapping
│           └── ai_remediation.py       # Remediation playbooks
└── frontend/
    ├── Dockerfile
    ├── package.json
    └── src/
        ├── App.jsx             # Routes + auth guard
        ├── api/client.js       # Axios with JWT injection
        └── pages/
            ├── DashboardPage.jsx   # HNDL charts, compliance heatmap
            ├── ScansPage.jsx       # Start scan, live progress
            ├── InfraGraphPage.jsx  # Interactive force-directed topology
            ├── AssetsPage.jsx      # Asset inventory table
            ├── FindingsPage.jsx    # Vulnerabilities + playbooks
            ├── CBOMPage.jsx        # CycloneDX viewer + download
```

---

##  Compliance Coverage

| Framework | Controls Checked |
|-----------|-----------------|
| NIST FIPS 203 | ML-KEM migration from RSA/ECC |
| NIST FIPS 204 | ML-DSA migration from ECDSA |
| NIST FIPS 205 | SLH-DSA alternative signatures |
| NIST IR 8547 | PQC readiness + hybrid deployment |
| CERT-In PQC Guidance 2024 | Indian critical infrastructure |
| RBI Master Direction IT 2023 | Banking quantum risk preparedness |
| RBI Cybersecurity Framework 4.2 | Encryption standards |

---

##  Database Schema

The system uses 9 PostgreSQL tables:

- `scan_jobs` — Scan metadata, status, progress
- `assets` — Discovered domains, IPs, protocols, HNDL scores
- `certificates` — TLS certificate details, algorithm, key size, expiry
- `cipher_suites` — Cipher suite names, TLS versions, quantum risk
- `findings` — Vulnerabilities with CWE IDs and HNDL scores
- `remediations` — Step-by-step migration playbooks
- `compliance_tags` — Mapping findings to framework controls
- `cboms` — CycloneDX JSON stored per scan
- `audit_logs` — All user actions logged for security

---

##  API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Health check status |
| POST | `/api/auth/login` | Login, returns JWT |
| GET | `/api/auth/me` | Get current user profile |
| POST | `/api/auth/logout` | Logout user |
| GET | `/api/dashboard` | All metrics for dashboard |
| GET | `/api/dashboard/stats` | Alias for dashboard metrics |
| POST | `/api/scans` | Start a new scan |
| GET | `/api/scans` | List all scans |
| GET | `/api/scans/{scan_id}` | Get scan status + progress |
| GET | `/api/scans/{scan_id}/findings`| All findings for a scan |
| GET | `/api/scans/{scan_id}/assets` | All assets for a scan |
| GET | `/api/scans/{scan_id}/graph` | Nodes & links for topology graph |
| GET | `/api/scans/{scan_id}/cbom` | CycloneDX CBOM for a scan |
| DELETE| `/api/scans/{scan_id}` | Delete a scan (Admin only) |
| GET | `/api/assets` | Asset inventory (filterable) |
| GET | `/api/assets/{asset_id}` | Asset detail with certs + ciphers |
| GET | `/api/assets/{asset_id}/findings`| Findings for a specific asset |

Full API docs available at `http://localhost/docs`

---

## ⚙️ Configuration

Edit `.env` to customize:

```env
POSTGRES_USER=qps_admin
POSTGRES_PASSWORD=your_secure_password
POSTGRES_DB=qps_scanner_db
SECRET_KEY=your_jwt_secret_key
ENVIRONMENT=production
```

---

##  Running Without Docker

```bash
# Install Python deps
pip install -r backend/requirements.txt

# Start backend
cd backend
uvicorn app.main:app --host 0.0.0.0 --port 8000

# Start Celery worker (separate terminal)
celery -A app.celery_app worker --loglevel=info -Q scans

# Start frontend (separate terminal)
cd frontend
npm install
npm run dev
```

Requires PostgreSQL and Redis running locally. Update `DATABASE_URL` and `REDIS_URL` in `.env` accordingly.

---

##  Competitive Advantage

| Capability | Qualys SSL Labs | Venafi | Censys | QuantumShield |
|-----------|:-:|:-:|:-:|:-:|
| CDN detection + bypass | ❌ | ❌ | ❌ | ✅ |
| HNDL risk scoring | ❌ | ❌ | ❌ | ✅ |
| CycloneDX CBOM | ❌ | Proprietary | ❌ | ✅ |
| Multi-protocol scan | ❌ | Partial | ❌ | ✅ |
| RBI/CERT-In mapping | ❌ | ❌ | ❌ | ✅ |
| AI remediation playbooks | ❌ | ❌ | ❌ | ✅ |
| No agent required | ✅ | ❌ | ✅ | ✅ |
| Docker one-command deploy | ❌ | ❌ | ❌ | ✅ |
| TLS version risk scoring | ❌ | ❌ | ❌ | ✅ |

---

## 👥 Team Spand — GEC Madhubani

| Name | Role |
|------|------|
| Ravi Choudhary | Team Lead |
| Purnima Kumari | Developer |
| Muskan Kumari | Tester |
| Gautam Singhal | Design & Research |

---

##  License

MIT License — open source, free to use and modify.

---

*Built for PSB Hackathon 2026 — Theme: Quantum-Proof Systems*