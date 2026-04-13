# 06 — Data Schema & Findings Handbook

QuantumShield maintain a relational security model that links every discovery back to a specific scan event, ensuring a complete audit trail.

## 🗄️ Core Database Tables (PostgreSQL)

| Table | Purpose | Key Fields |
| :--- | :--- | :--- |
| **`scan_jobs`** | The "Top-Level" object. | `org_name`, `status`, `progress`, `target_assets` |
| **`assets`** | individual subdomains found. | `domain`, `network_type`, `hndl_score`, `is_cdn` |
| **`certificates`** | TLS certificate details. | `algorithm`, `key_size`, `subject`, `issuer`, `expires_at` |
| **`cipher_suites`** | Cipher suites per asset. | `name`, `tls_version`, `quantum_risk` |
| **`findings`** | specific vulnerabilities. | `severity`, `title`, `description`, `cwe_id` |
| **`remediations`** | AI-generated playbooks. | `steps`, `priority`, `pqc_alternative` |
| **`compliance_tags`**| Mapping to standards. | `framework`, `control_ref`, `status` |
| **`cboms`** | CycloneDX JSON results. | `content` (CycloneDX 1.4 schema) |
| **`users`** | RBAC credentials. | `username`, `role` (Admin, Analyst, SOC, etc.) |

---

## 🛠️ The CycloneDX CBOM (Cryptographic Bill of Materials)

QuantumShield is a pioneer in **CBOM generation**. At the end of every scan, the `cbom_generator.py` engine assembles all discovered assets, certificates, and ciphers into a standardized CycloneDX JSON blob.

### Key CBOM Fields
- **Components**: The specific assets scanned (e.g., `api.example.com`).
- **CryptoProperties**: The detailed cryptographic metadata (Algorithm, Mode, KeySize).
- **Vulnerabilities**: Linked findings with HNDL scores and severity.

This file can be exported and imported into high-level risk management platforms for enterprise reporting.

---

## 🤖 AI Remediation Logic

When a vulnerability is found (e.g., RSA-2048), the system doesn't just flag it. It generates a **Remediation Playbook**:
1. **Detection**: Identify the weak algorithm.
2. **Context**: Check the port (HTTPS vs SSH vs SMTP).
3. **PQC Alternative**: Map to the correct ML-KEM/ML-DSA parameter.
4. **Step-by-Step**: Provide server-specific config instructions (Nginx, OpenSSL, etc.) to upgrade to quantum-safe settings.
