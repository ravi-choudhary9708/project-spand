"""
AI-Assisted Remediation Engine
Generates step-by-step remediation playbooks for cryptographic vulnerabilities.
"""
from typing import List, Dict, Any


REMEDIATION_PLAYBOOKS = {
    "RSA": {
        "title": "Migrate from RSA to Post-Quantum Algorithm",
        "pqc_alternative": "CRYSTALS-Kyber (ML-KEM) / CRYSTALS-Dilithium (ML-DSA)",
        "priority": 9,
        "steps": [
            "1. Inventory all RSA certificates and keys in use across assets.",
            "2. Assess urgency using HNDL score — prioritize assets with high data sensitivity and long certificate lifetimes.",
            "3. Evaluate NIST-approved PQC alternatives: ML-KEM (CRYSTALS-Kyber) for key exchange, ML-DSA (CRYSTALS-Dilithium) for signatures.",
            "4. Implement hybrid TLS — run Classical + PQC simultaneously during transition (X25519Kyber768 hybrid).",
            "5. Update certificate authorities to issue PQC or hybrid certificates.",
            "6. Update all client libraries that rely on RSA key pairs.",
            "7. Test PQC compatibility with all dependent services.",
            "8. Deploy PQC keys in staging, monitor for failures.",
            "9. Roll out PQC certificates to production.",
            "10. Revoke and retire old RSA certificates.",
        ],
    },
    "ECC": {
        "title": "Migrate from Elliptic Curve Cryptography to PQC",
        "pqc_alternative": "CRYSTALS-Kyber (ML-KEM) / CRYSTALS-Dilithium (ML-DSA)",
        "priority": 9,
        "steps": [
            "1. Identify all ECC key pairs (ECDSA, ECDH, ECDHE) in use.",
            "2. Calculate HNDL score for each asset — ECC is vulnerable to Shor's algorithm.",
            "3. Replace ECDH/ECDHE key exchange with ML-KEM (FIPS 203).",
            "4. Replace ECDSA signatures with ML-DSA (FIPS 204) or SLH-DSA (FIPS 205).",
            "5. Use hybrid PQC+Classical during transition period.",
            "6. Update TLS configurations to prefer ML-KEM cipher suites.",
            "7. Renew all ECC certificates with PQC or hybrid alternatives.",
            "8. Validate updated configurations with TestSSL and SSLyze.",
        ],
    },
    "DH": {
        "title": "Replace Diffie-Hellman Key Exchange",
        "pqc_alternative": "CRYSTALS-Kyber (ML-KEM)",
        "priority": 8,
        "steps": [
            "1. Identify all services using DHE or FFDHE key exchange.",
            "2. Replace DHE with ECDHE as an interim measure (still quantum-vulnerable but stronger classically).",
            "3. Plan migration to ML-KEM for quantum-safe key exchange.",
            "4. Configure TLS to disable export-grade and weak DH groups.",
            "5. Update cipher suite priority to prefer forward-secure, PQC-ready options.",
        ],
    },
    "TLS_OUTDATED": {
        "title": "Upgrade TLS Protocol Version",
        "pqc_alternative": "TLS 1.3 with PQC cipher suites",
        "priority": 8,
        "steps": [
            "1. Disable TLS 1.0 and TLS 1.1 on all endpoints.",
            "2. Configure minimum TLS version to TLS 1.2 (TLS 1.3 preferred).",
            "3. Update server configuration (nginx/apache/openssl) with strong cipher suites.",
            "4. Enable TLS 1.3 which supports only forward-secure cipher suites.",
            "5. Test with TestSSL to confirm no older TLS versions are supported.",
            "6. Add HSTS headers to prevent TLS downgrade attacks.",
        ],
    },
    "WEAK_CIPHER": {
        "title": "Replace Weak Cipher Suites",
        "pqc_alternative": "ChaCha20-Poly1305 or AES-256-GCM",
        "priority": 7,
        "steps": [
            "1. Use TestSSL to enumerate all supported cipher suites.",
            "2. Disable NULL, EXPORT, RC4, DES, 3DES, and ANON cipher suites.",
            "3. Enable only AEAD cipher suites: AES-256-GCM, CHACHA20-POLY1305.",
            "4. Prefer cipher suites with forward secrecy (ECDHE-*, DHE-*).",
            "5. Validate changes with SSLyze and testssl.sh.",
        ],
    },
    "EXPIRED_CERT": {
        "title": "Renew Expired Certificate",
        "pqc_alternative": "Issue new certificate with PQC-ready CA",
        "priority": 10,
        "steps": [
            "1. Immediately renew the expired certificate (high urgency).",
            "2. Consider using a PQC-ready or hybrid certificate if CA supports it.",
            "3. Set up automated certificate renewal (Let's Encrypt / ACME protocol).",
            "4. Monitor certificate expiry dates with alerting (30/14/7 day warnings).",
            "5. Validate renewed certificate is properly deployed across all servers.",
        ],
    },
}


def get_remediation_playbook(finding_type: str, algorithm: str = "") -> Dict[str, Any]:
    """Get remediation steps for a given finding type."""
    algo_upper = algorithm.upper() if algorithm else ""

    # Match by algorithm
    for key, playbook in REMEDIATION_PLAYBOOKS.items():
        if key in algo_upper:
            return playbook

    # Match by finding type
    type_map = {
        "OUTDATED_TLS": "TLS_OUTDATED",
        "WEAK_CIPHER": "WEAK_CIPHER",
        "EXPIRED_CERT": "EXPIRED_CERT",
        "QUANTUM_VULNERABLE_ALGO": "RSA",
        "HNDL_RISK": "RSA",
        "WEAK_KEY_SIZE": "RSA",
    }

    mapped = type_map.get(finding_type.upper(), "RSA")
    return REMEDIATION_PLAYBOOKS.get(mapped, REMEDIATION_PLAYBOOKS["RSA"])


def calculate_priority_score(hndl_score: float, asset_criticality: float = 5.0) -> float:
    """
    SRS FR-16: Priority Score = Risk Score × Asset Criticality
    """
    return round(min(hndl_score * asset_criticality / 10.0 * 10.0, 10.0), 2)
