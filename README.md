# 🔐 QuantumShield — Quantum-Proof Systems Scanner

**PSB Hackathon 2026 | Team Spand | GEC Madhubani**

> A tool that scans public-facing infrastructure for quantum cryptography vulnerabilities, generates CycloneDX CBOM reports, and maps findings to NIST PQC, RBI, and CERT-In compliance frameworks.

---

## 🚀 Quick Start

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

## 🎯 What It Does

QuantumShield scans your organization's public-facing domains and tells you:

1. **Which assets are vulnerable to quantum attacks** (RSA, ECC, Diffie-Hellman)
2. **How urgent the risk is** via HNDL (Harvest-Now-Decrypt-Later) score 0–10
3. **Which compliance frameworks you are violating** (NIST FIPS 203/204/205, RBI, CERT-In)
4. **Exactly what to do to fix it** via step-by-step remediation playbooks
5. **A complete Cryptographic Bill of Materials (CBOM)** in CycloneDX 1.4 format

---

## 📊 Key Features

| Feature | Description |
|---------|-------------|
| **Asset Discovery** | Subfinder + CT logs + DNS — discovers all public subdomains automatically |
| **HNDL Scoring** | Weighted formula: Algorithm × 0.40 + Key Size × 0.20 + Data Sensitivity × 0.20 + TLS Version × 0.10 + Cert Expiry × 0.10 |
| **CycloneDX CBOM** | Industry-standard Cryptographic Bill of Materials, exportable as JSON or XML |
| **Compliance Mapping** | Automatic mapping to NIST FIPS 203/204/205, NIST IR 8547, RBI, CERT-In |
| **AI Remediation** | Step-by-step migration playbooks for RSA → ML-KEM, ECC → ML-DSA |
| **Multi-protocol** | HTTPS, SMTP, IMAP, SSH, VPN, FTPS |
| **RBAC Dashboard** | 5 user roles — Admin, Analyst, Compliance, SOC, Management |
| **Continuous Monitoring** | Celery Beat schedules daily rescans automatically |
| **CDN Detection** | Detects Cloudflare, Akamai, Fastly and attempts origin bypass |
| **Full Org / Custom URL** | Scan an entire organization or a single specific URL |

---

## 🌐 Scan Modes

### Full Organization Scan (Default)

By default, the **"Full Organization Scan"** checkbox is checked. When you enter a domain like `pnb.in`, the scanner will:
- Discover **all subdomains** via subfinder (`netbanking.pnb.bank.in`, `creditcard.pnb.bank.in`, etc.)
- Scan every discovered subdomain for quantum vulnerabilities
- Build a complete picture of your organization's cryptographic posture

### Custom URL Scan

> **💡 To scan only a specific URL, uncheck the "Full Organization Scan" checkbox.**

When unchecked, the scanner will **only scan the exact URL you provide** — no subdomain discovery. This is useful when:
- You want to scan a single service like `aws.amazon.com`
- You're testing a specific endpoint
- You want faster results for a single target

---

## 🔬 How the Scan Works — Complete Pipeline

When you click "Start Scan" and enter a domain:

### Step 1: Input Cleaning
The target URL is stripped of `http://`, `https://`, paths, and trailing slashes to get a bare domain.

### Step 2: Subdomain Discovery (Full Org Scan only)
**Subfinder** discovers all public subdomains using passive sources (APIs, DNS records, CT logs).
If subfinder is unavailable, a DNS fallback tries common prefixes (`www`, `mail`, `api`, `ftp`, `vpn`, etc.).

### Step 3: CT Log Cache
Certificate Transparency logs are queried **once** per root domain from [crt.sh](https://crt.sh). A local `crt.txt` file is checked first as a warm cache. This provides algorithm + expiry data for ALL subdomains — even CDN-protected and firewall-blocked ones.

### Step 4: Per-Domain Scanning

For each domain, the scanner runs through this pipeline:

#### 4a. DNS Resolution
Resolves the domain to IP addresses using `socket.getaddrinfo()`.

#### 4b. CDN Detection
Checks if the IP belongs to Cloudflare, Akamai, Fastly, or other CDN providers by reverse-DNS lookup.

#### 4c. Port Scan (Optimized)
Scans **only TLS-relevant ports** (not all 65535):
```
443, 8443, 25, 587, 465, 143, 993, 110, 995, 21, 990, 22, 1194, 1723, 500
```
- **Nmap** (if available): Fast SYN scan (`-sS -T4`) — completes in ~5 seconds
- **Fallback**: Concurrent socket checks via ThreadPoolExecutor — all 15 ports checked simultaneously in ~1.5 seconds

#### 4d. Protocol Detection
Maps open ports to protocols: 443→HTTPS, 22→SSH, 25/587→SMTP, 993→IMAP, 995→POP3, 990→FTPS, 1194/1723/500→VPN.

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

## 📐 HNDL Risk Score Formula

```
HNDL Score (0–10) =
  (Algorithm Vulnerability Score  × 0.40)     ← 40% weight
+ (Key Size Risk Score            × 0.20)     ← 20% weight
+ (Data Sensitivity Weight        × 0.20)     ← 20% weight
+ (TLS Version Risk               × 0.10)     ← 10% weight
+ (Certificate Expiry Risk        × 0.10)     ← 10% weight
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

## 🏗️ Architecture

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

### Tech Stack

**Backend:** Python 3.11, FastAPI, SQLAlchemy, PostgreSQL, Celery, Redis

**Frontend:** React 18, Vite, Recharts, Axios

**Scanning Tools:** Nmap, TestSSL, SSLyze, Subfinder, OpenSSL, Python `cryptography`

**Infrastructure:** Docker Compose, Nginx

---

## 📁 Project Structure

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
            ├── AssetsPage.jsx      # Asset inventory table
            ├── FindingsPage.jsx    # Vulnerabilities + playbooks
            └── CBOMPage.jsx        # CycloneDX viewer + download
```

---

## 🛡️ Compliance Coverage

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

## 🗄️ Database Schema

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

## 🔑 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/login` | Login, returns JWT |
| GET | `/api/dashboard` | All metrics for dashboard |
| POST | `/api/scans` | Start a new scan |
| GET | `/api/scans` | List all scans |
| GET | `/api/scans/{id}` | Get scan status + progress |
| GET | `/api/scans/{id}/findings` | All findings for a scan |
| GET | `/api/scans/{id}/cbom` | CycloneDX CBOM for a scan |
| GET | `/api/assets` | Asset inventory (filterable) |
| GET | `/api/assets/{id}` | Asset detail with certs + ciphers |

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

## 🏃 Running Without Docker

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

## 🔍 Competitive Advantage

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

## 📜 License

MIT License — open source, free to use and modify.

---

*Built for PSB Hackathon 2026 — Theme: Quantum-Proof Systems*