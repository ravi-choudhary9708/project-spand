# Advanced TLS Security Scanning Architecture

This document describes the high-concurrency, multi-stage scanning architecture utilized by QuantumShield to identify cryptographic vulnerabilities and calculate the **Harvest Now, Decrypt Later (HNDL)** risk score across large asset inventories.

---

## ── ARCHITECTURAL PHILOSOPHY ───────────────────────────────────────

The scanner is designed for **High Fidelity at Scale**. It solves the "WAF/CDN Problem" (where edge nodes hide the true server certificates) by using a decoupled pipeline that separates intelligence gathering from security analysis.

---

## ── SCANNING PIPELINE (The "Execution Engine") ────────────────────

The `run_full_scan` Celery task follows a four-stage parallel pipeline:

### 1. Discovery Stage
*   **Tool**: `subfinder`
*   **Action**: Performs passive subdomain discovery via API mining (BinaryEdge, C99, many others).
*   **Parallelism**: Singular execution, but highly concurrent internally.

### 2. Root Intelligence Stage (Parallel)
*   **Action**: Rapidly gathers global metadata for each root domain.
*   **Parallelism**: 5 Threads.
*   **Data Points**:
    *   **CT Logs**: Builds a root certificate cache from `crt.sh`.
    *   **SPF Mining**: Extracts mail-server/origin IPs from DNS TXT records.
    *   **Passive DNS**: Fetches historical A-records (ViewDNS) to find pre-CDN IPs.

### 3. Target Profiling Stage (Parallel)
*   **Action**: Expands discovery results into detailed `TargetProfile` objects.
*   **Parallelism**: 15 Threads.
*   **Utility**: Bundles pre-discovered bypass candidates and metadata into a read-only object for the final worker, eliminating mid-scan network blocking.

### 4. Security Analysis Stage (Parallel)
*   **Action**: Executes heavy-duty network probes and cryptographic handshakes.
*   **Parallelism**: 5 Workers (Moderated via `MAX_PARALLEL_DOMAINS`).
*   **Flow**:
    *   **Nmap**: Fast SYN scan for open TLS ports.
    *   **Crytographic Engine**: Orchestrated priority (Testssl → SSLyze → OpenSSL).
    *   **Scoring & Persistence**: Calculates HNDL and saves to DB.

---

## ── THE THREE-PATH ALGORITHM ──────────────────────────────────────

To ensure 100% data coverage even when direct connections are blocked, the scanner utilizes a tiered decision engine:

### [PATH A] Direct Verification (Verified)
*   **Trigger**: TLS port is open and accessible.
*   **Logic**: A direct handshake is performed (Testssl/OpenSSL) to retrieve the **live leaf certificate** and cipher suites.
*   **Confidence**: `VERIFIED`

### [PATH B1] Origin Bypass (Verified)
*   **Trigger**: Path A fails (WAF blocks scanner / CDN hides cert).
*   **Logic**: The scanner attempts to connect directly to **Origin IPs** (mined from SANs, SPF, or Passive DNS) while sending the target domain as TLS SNI.
*   **Benefit**: Reveals the true server algorithm behind the CDN.
*   **Confidence**: `VERIFIED`

### [PATH B2] CT Log Fallback (Approximate)
*   **Trigger**: Paths A and B1 both fail.
*   **Logic**: Uses the pre-buffered CT Log cache to check the most recently logged certificate for the domain. 
*   **Caveat**: Algorithms are inferred from the Issuer Name (e.g., "DigiCert ECC CA" → ECDSA).
*   **Confidence**: `APPROXIMATE`

### [PATH C] Conservative Default
*   **Trigger**: No data found.
*   **Logic**: Assumes a conservative baseline (RSA-2048) and marks the asset as a candidate for manual review.
*   **Confidence**: `DEFAULT`

---

## ── CRYPTOGRAPHIC ENGINE PRIORITY ───────────────────────────────

The scanner orchestrates multiple tools to maximize detail:

| Priority | Tool | Purpose | Reliability |
| :--- | :--- | :--- | :--- |
| **1** | `testssl.sh` | Full cipher enumeration + Vulnerability detection (BEAST/LUCKY13) | High |
| **2** | `SSLyze` | Cipher filling and additional protocol metadata | High |
| **3** | `OpenSSL CLI` | Rapid certificate extraction (PEM/Expiry/Issuer) | High |
| **4** | `Python SSL` | Fallback basic handshake for algorithm identification | Medium |

---

## ── SCORING & FINDINGS ──────────────────────────────────────────

### HNDL (Harvest Now, Decrypt Later) Score
Calculated as a weighted value (0.0 - 10.0) based on:
1.  **Algorithm**: (e.g., RSA = 10.0 risk, Kyber = 0.0 risk).
2.  **Key Size**: Strength against classic attacks.
3.  **Protocol**: TLS version (TLS 1.3 is superior).
4.  **Expiry**: Time remaining until natural rotation.
5.  **Sensitivity**: Importance of the assets (e.g., `.bank.in` vs `.dev`).

### Compliance Mapping
Every vulnerability or weak algorithm is automatically mapped to:
*   **FIPS 140-3** (Post-Quantum Readiness)
*   **NIST SP 800-52**
*   **PCI-DSS v4.0** (Insecure Protokols)

---

## ── THREAD SAFETY & SCALABILITY ───────────────────────────────

*   **Database**: Every worker thread maintains an isolated SQLAlchemy session.
*   **Locking**: The gathering phase is read-only for the analysis workers, eliminating the need for complex mutexes during heavy scanning.
*   **Concurrency**: Tuned via `concurrency` flags in Celery workers and `MAX_PARALLEL_DOMAINS` in `scan_tasks.py`.
