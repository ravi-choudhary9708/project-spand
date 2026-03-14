# Quantum-Proof Systems Scanner

This project is a comprehensive cryptographic inventory and quantum-readiness assessment tool, built for the PSB Hackathon 2026.

## Features
- **Asset Discovery:** Identifies domains, subdomains, and resolved IPs.
- **TLS & Cipher Scanning:** Scans for certificates, protocols, Open Ports, and Cipher Suites.
- **HNDL Score:** Calculates Harvest Now, Decrypt Later risk scores.
- **PQC Readiness Assessment:** Evaluates algorithms against Shor's algorithm vulnerability.
- **Compliance Mapping:** Maps findings to NIST PQC, CERT-In, and RBI guidelines.
- **AI Remediation Playbooks:** Provides actionable steps for mitigating cryptographic risks.
- **CBOM Generation:** Generates Cryptographic Bill of Materials in CycloneDX JSON/XML formats.

## Architecture
- **Backend:** FastAPI (Python), SQLAlchemy, PostgreSQL
- **Task Queue:** Celery with Redis broker
- **Frontend:** React (Vite.js) with Recharts
- **Infrastructure:** Docker Compose, Nginx Reverse Proxy

## Getting Started

### Prerequisites
- Docker and Docker Compose installed
- Internet connection (for external scanning tools and asset discovery)

### Starting the System

Simply run the following command in the root of the project:

```bash
docker-compose up -d --build
```

Wait 1-2 minutes for all containers to build and initialize. The database will automatically be seeded with default users.

### Accessing the Application

- **Web UI:** `http://localhost`
- **Backend API Docs:** `http://localhost/docs`

### Default Credentials
| Role | Username | Password |
| :--- | :--- | :--- |
| **Admin** | `admin` | `admin123` |
| **Security Analyst** | `analyst` | `analyst123` |
| **Compliance Officer** | `compliance` | `comply123` |
| **SOC Team** | `soc` | `soc123` |
| **Management** | `manager` | `manager123` |

## Components Overview

1. **Dashboard:** High-level metrics, PQC readiness breakdown, HNDL distribution, and compliance violation heatmaps.
2. **Scans:** Initiate new scans by providing a list of target domains/IPs. Monitors live progress of the scanning pipeline.
3. **Assets:** Searchable, filterable inventory of all discovered assets and their cryptographic properties.
4. **Findings:** Detailed view of vulnerabilities including CWE mappings, HNDL impact, and remediation playbooks.
5. **CBOM:** Generate and download standard CycloneDX Cryptographic Bill of Materials for any completed scan.

## License
MIT
