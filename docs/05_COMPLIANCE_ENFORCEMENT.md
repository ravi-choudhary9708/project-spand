# 05 — Compliance Enforcement

QuantumShield maps every cryptographic finding to international and regional compliance standards, ensuring that organizations can demonstrate "Quantum Readiness" to auditors.

## 🏛️ Supported Frameworks

### 1. NIST PQC Standards (Global)
- **FIPS 203**: ML-KEM (formerly Kyber) for key encapsulation.
- **FIPS 204**: ML-DSA (formerly Dilithium) for digital signatures.
- **FIPS 205**: SLH-DSA (formerly SPHINCS+) as a backup signature scheme.
- *Mapping*: Any finding using RSA/ECC triggers a "Non-Compliant" status for FIPS 203/204.

### 2. Indian Banking & Financial (RBI)
- **RBI Master Direction — IT Framework 2023**: Section on encryption and risk assessment.
- **RBI Cybersecurity Framework 4.2**: Requirements for strong encryption (AES, RSA-2048+).
- *Mapping*: Use of legacy ciphers (3DES, RC4) or weak RSA triggers high-priority RBI violations.

### 3. Critical Infrastructure (CERT-In)
- **CERT-In PQC Guidance 2024**: Targeted advisory for Indian government and critical infrastructure.
- *Mapping*: RSA/ECC in government-linked domains is flagged as CRITICAL under CERT-In guidance.

---

## 📊 Compliance Status Logic

For every finding, the **Compliance Engine** (`compliance_engine.py`) returns a status:

- **COMPLIANT**: Asset uses NIST-approved PQC algorithms or quantum-resistant hybrid schemes.
- **NON_COMPLIANT**: Asset relies on vulnerabilities mapped to specific standard controls.
- **NEEDS_ATTENTION**: Asset uses acceptable classical crypto (like RSA-4096) but requires a PQC migration path under NIST IR 8547.
