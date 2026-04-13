# 04 — HNDL Scoring: The Science of Risk

The **Harvest Now, Decrypt Later (HNDL)** score is the heart of QuantumShield's risk assessment. It moves beyond binary "vulnerable" labels to provide a nuanced, 0–10 risk metric.

## 📐 The HNDL Formula

```text
HNDL Score = (Algorithm × 0.40) + (KeySize × 0.20) + (Sensitivity × 0.20) + (TLS × 0.10) + (Expiry × 0.10)
```

### 1. Algorithm Vulnerability (40%)
The most critical factor. We use the **Shor's Algorithm impact matrix**:
- **RSA-2048 / ECC**: 9.0–9.5 (Critical)
- **AES-128**: 3.0 (Medium - halved by Grover's)
- **ML-KEM / ML-DSA**: 0.5 (Quantum Safe)

### 2. Key Size Risk (20%)
Larger keys provide slightly more headroom, though most remain fundamentally broken by quantum logic.
- **RSA 4096**: 3.0
- **RSA 2048**: 7.0
- **RSA 1024**: 9.0

### 3. Data Sensitivity (20%)
We auto-calculate sensitivity based on subdomain patterns:
- **Critical (10.0)**: `netbanking`, `pay`, `swift`, `cbdc`, `rtgs`, `vault`.
- **High (9.0)**: `vpn`, `auth`, `login`, `idp`.
- **Medium (5.0)**: `www`, `api`, `dev`, `test`.
- **Low (2.0)**: `static`, `assets`, `cdn`.

### 4. TLS Version (10%)
- **TLS 1.3**: 1.0 (Safe)
- **TLS 1.2**: 4.0 (Acceptable)
- **TLS 1.0/1.1**: 9.0 (Critical)

### 5. Certificate Expiry (10%)
Certificates with long validity periods pose a higher HNDL risk as they may still be in use when cryptographically relevant quantum computers arrive.

---

## 🚦 Risk Labels

| Score | Label | Action |
| :--- | :--- | :--- |
| **0.0 - 3.0** | 🟢 **Quantum Safe** | Monitor for algorithm updates. |
| **3.1 - 5.5** | 🟡 **Partially Safe** | Review for high-sensitivity data. |
| **5.6 - 7.8** | 🟠 **Vulnerable** | Begin migration planning for ML-KEM. |
| **7.9 - 10.0** | 🔴 **Critical Risk** | High-priority migration target. |
