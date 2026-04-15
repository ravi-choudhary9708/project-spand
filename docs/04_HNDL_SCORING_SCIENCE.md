# 04 — HNDL Scoring: The Science of Risk

The **Harvest Now, Decrypt Later (HNDL)** score is the heart of QuantumShield's risk assessment. In Version 2, the scoring engine has evolved from a simple weighted sum to a context-aware risk model that accounts for data longevity, session security, and technical penalties.

## 📐 The HNDL v2 Formula

The final risk score is calculated by combining a **Base Cryptographic Score (BCS)** with four **Context Multipliers**:

```text
HNDL_final = min(10.0, BCS × W_sensitivity × M_shelf × M_pfs × M_tls_version)
```

### 1. Base Cryptographic Score (BCS)
The BCS represents the inherent mathematical risk of the cryptographic setup:
```text
BCS = (AlgoVuln × 0.50) + (KeySizeRisk × 0.20) + (TLSRisk × 0.20) + (ExpiryRisk × 0.10)
```
- **Algorithm Vulnerability (50%)**: Based on Shor’s Algorithm impact (RSA/ECC: 9.0–9.5, AES-128: 3.0).
- **Key Size Risk (20%)**: Higher risk for shorter keys (RSA-2048: 7.0 vs RSA-4096: 3.0).
- **TLS Protocol Risk (20%)**: Risk of the underlying handshake protocol (TLS 1.0: 9.0, TLS 1.3: 1.0).
- **Expiry Risk (10%)**: Certificates that expire in the distant future pose higher HNDL risk as they may still be active when practical quantum computers emerge.

---

## 🚀 Context Multipliers

Multipliers amplify or reduce the BCS based on the environment of the asset.

### 1. Data Sensitivity Weight (W_sensitivity)
*Range: 0.8 → 1.5*
Automatically inferred from subdomain keywords:
- **Critical (1.50)**: `netbanking`, `swift`, `cbdc`, `rtgs`, `vault`.
- **Identity (1.40)**: `vpn`, `auth`, `login`, `idp`, `mfa`.
- **API/Gateway (1.20)**: `api`, `gateway`, `upi`, `rest`.
- **Static (0.80)**: `cdn`, `static`, `assets`.

### 2. Data Shelf-Life Multiplier (M_shelf)
*Range: 0.2 → 1.0*
Determines how long the captured data remains valuable to an attacker:
- **Ephemeral (0.20)**: OTPs, captchas, nonces (useless if decrypted years later).
- **Persistent (1.00)**: KYC data, Aadhaar, PAN, birth records, long-term legal archives.

### 3. Perfect Forward Secrecy Benefit (M_pfs)
*Fixed: 0.85 or 1.0*
- **0.85 (Reward)**: Using ECDHE or DHE. Prevents retroactive decryption of entire traffic streams if the long-term private key is compromised.
- **1.00 (Neutral)**: Static RSA key exchange; no forward secrecy.

### 4. TLS Version Penalty (M_tls_version)
*Range: 0.85 → 1.30*
- **TLS 1.3 (0.85)**: Rewarded for modern, secure defaults.
- **TLS 1.0/SSLv3 (1.15 - 1.30)**: Penalized for protocol-level weaknesses.

---

## 🛑 The PQC Kill Switch

If an asset is detected using a NIST-standardized Post-Quantum algorithm (**ML-KEM**, **ML-DSA**, or **SLH-DSA**), the scoring engine activates the **PQC Kill Switch**. 

All mathematical risk calculations are bypassed, and the asset is assigned a flat **0.5 (Quantum Safe)** score.

---

## 🚦 Risk Labels

| Score | Label | Action |
| :--- | :--- | :--- |
| **0.0 - 1.0** | 🟢 **Quantum Safe** | Using PQC-ready algorithms. |
| **1.1 - 3.5** | 🟡 **Partially Safe** | Some risk, consider hybrid migration. |
| **3.6 - 6.5** | 🟠 **Vulnerable** | Begin migration planning for ML-KEM. |
| **6.6 - 10.0** | 🔴 **Critical Risk** | High-priority migration target. |
