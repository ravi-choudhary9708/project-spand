# 🔐 QuantumShield — Quantum-Proof Systems Scanner

**PSB Hackathon 2026 | Team Spand | GEC Madhubani**

> A  tool that scans public-facing infrastructure for quantum cryptography vulnerabilities, generates CycloneDX CBOM reports, and maps findings to NIST PQC, RBI, and CERT-In compliance frameworks.

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

spand scans your organization's public-facing domains and tells you:

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
| **HNDL Scoring** | Weighted formula: Algorithm × 0.40 + Key Size × 0.20 + Data Sensitivity × 0.30 + Cert Expiry × 0.10 |
| **CycloneDX CBOM** | Industry-standard Cryptographic Bill of Materials, exportable as JSON or XML |
| **Compliance Mapping** | Automatic mapping to NIST FIPS 203/204/205, NIST IR 8547, RBI, CERT-In |
| **AI Remediation** | Step-by-step migration playbooks for RSA → ML-KEM, ECC → ML-DSA |
| **Multi-protocol** | HTTPS, SMTP, IMAP, SSH, VPN, FTPS |
| **RBAC Dashboard** | 5 user roles — Admin, Analyst, Compliance, SOC, Management |
| **Continuous Monitoring** | Celery Beat schedules daily rescans automatically |
| **CDN Detection** | Detects Cloudflare, Akamai, Fastly and attempts origin bypass |

---

## 🏗️ Architecture

```
Browser (React)
    ↓
Nginx (reverse proxy)
    ↓
FastAPI Backend (Python)
    ↓
Celery Worker (async scan)
    ↓ ↓ ↓ ↓ ↓
subfinder  nmap  TLS  HNDL  CBOM
    ↓
PostgreSQL (results)
Redis (task queue)
```

### Tech Stack

**Backend:** Python 3.11, FastAPI, SQLAlchemy, PostgreSQL, Celery, Redis

**Frontend:** React 18, Vite, Recharts, Axios

**Scanning Tools:** Nmap, TestSSL, SSLyze, Subfinder, OpenSSL

**Infrastructure:** Docker Compose, Nginx

---

## 📁 Project Structure

```
qps-scanner/
├── docker-compose.yml          # Starts all 6 containers
├── .env                        # Environment variables
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
│       │   └── scanner.py      # subfinder, DNS, nmap, TLS scan
│       ├── tasks/
│       │   └── scan_tasks.py   # Full 17-step scan pipeline
│       └── engines/
│           ├── hndl_engine.py          # HNDL risk formula
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

## 🔬 How the Scan Works

When you click "Start Scan" and enter a domain like `pnb.in`:

1. **Asset Discovery** — Subfinder discovers all subdomains (`netbanking.pnb.bank.in`, `creditcard.pnb.bank.in`, etc.)
2. **DNS Resolution** — Each subdomain resolved to IP addresses
3. **CDN Detection** — Checks if Cloudflare/Akamai is in front
4. **Port Scan** — Nmap scans ports 443, 22, 25, 587, 993, 990, etc.
5. **Protocol Detection** — Maps open ports to protocols (443=HTTPS, 22=SSH, 25=SMTP)
6. **TLS Scan** — Connects to each HTTPS endpoint, extracts certificate + cipher suite
7. **HNDL Scoring** — Calculates risk score using the formula below
8. **Compliance Mapping** — Maps each finding to NIST/RBI/CERT-In controls
9. **Remediation** — Generates migration playbook for each vulnerability
10. **CBOM Generation** — Creates CycloneDX 1.4 JSON with all findings

---

## 📐 HNDL Risk Score Formula

```
HNDL Score (0–10) =
  (Algorithm Vulnerability Score  × 0.40)
+ (Key Size Risk Score            × 0.20)
+ (Data Sensitivity Weight        × 0.30)
+ (Certificate Expiry Risk        × 0.10)
```

**Algorithm scores:** RSA-2048 = 9.0, ECDSA = 9.0, DHE = 8.0, ML-KEM = 0.5

**Data sensitivity** is inferred from subdomain name:
- `netbanking.*`, `payment.*` → 10.0
- `vpn.*`, `auth.*` → 9.0
- `api.*`, `gateway.*` → 7.5
- `cdn.*`, `static.*` → 2.0

**Risk labels:**
- 0.0–3.0 → Quantum Safe
- 3.1–5.5 → Partially Safe
- 5.6–7.8 → Vulnerable
- 7.9–10.0 → Critical Risk

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