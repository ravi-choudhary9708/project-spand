"""
AI-Assisted Remediation Engine
Generates step-by-step PQC migration playbooks for cryptographic vulnerabilities.
Place at: backend/app/engines/ai_remediation.py
"""
from typing import Dict, Any


REMEDIATION_PLAYBOOKS = {
    "RSA": {
        "title": "Migrate from RSA to Post-Quantum Algorithm",
        "pqc_alternative": "ML-KEM (CRYSTALS-Kyber) / ML-DSA (CRYSTALS-Dilithium)",
        "priority": 9,
        "steps": [
            "1. Inventory all RSA certificates and keys across all assets.",
            "2. Calculate HNDL score — assets with score >7.0 are high priority.",
            "3. Evaluate NIST-approved PQC alternatives: ML-KEM (FIPS 203) for key exchange, ML-DSA (FIPS 204) for signatures.",
            "4. Implement hybrid TLS — run Classical + PQC simultaneously during transition (X25519Kyber768 hybrid key exchange).",
            "5. Update your CA infrastructure to issue PQC or hybrid certificates.",
            "6. Update all client libraries and SDKs that rely on RSA key pairs.",
            "7. Test PQC compatibility with all dependent services and integrations.",
            "8. Deploy PQC keys in staging environment and monitor for failures.",
            "9. Roll out PQC certificates to production.",
            "10. Revoke and retire all old RSA certificates after successful migration.",
        ],
    },
    "ECC": {
        "title": "Migrate from Elliptic Curve Cryptography to PQC",
        "pqc_alternative": "ML-KEM (CRYSTALS-Kyber) / ML-DSA (CRYSTALS-Dilithium)",
        "priority": 9,
        "steps": [
            "1. Identify all ECC key pairs — includes ECDSA, ECDH, ECDHE variants.",
            "2. Note: ECC is fully vulnerable to Shor's algorithm on a quantum computer.",
            "3. Replace ECDH/ECDHE key exchange with ML-KEM (FIPS 203).",
            "4. Replace ECDSA signatures with ML-DSA (FIPS 204) or SLH-DSA (FIPS 205).",
            "5. Use hybrid PQC + Classical cipher suites during the transition period.",
            "6. Update TLS configurations to prefer ML-KEM key exchange cipher suites.",
            "7. Renew all ECC certificates with PQC or hybrid alternatives from your CA.",
            "8. Validate updated configurations using TestSSL and SSLyze after deployment.",
        ],
    },
    "DH": {
        "title": "Replace Diffie-Hellman Key Exchange",
        "pqc_alternative": "ML-KEM (CRYSTALS-Kyber)",
        "priority": 8,
        "steps": [
            "1. Identify all services using DHE or FFDHE key exchange.",
            "2. Disable weak DH groups — minimum 2048-bit DH if classical DH must remain.",
            "3. Replace DHE with ECDHE as an interim classical-safe measure.",
            "4. Plan full migration to ML-KEM for quantum-safe key exchange.",
            "5. Update cipher suite priority to disable DHE and prefer ML-KEM groups.",
        ],
    },
    "TLS_OUTDATED": {
        "title": "Upgrade TLS Protocol Version",
        "pqc_alternative": "TLS 1.3 with PQC cipher suites",
        "priority": 8,
        "steps": [
            "1. Immediately disable TLS 1.0 and TLS 1.1 on all endpoints.",
            "2. Set minimum TLS version to TLS 1.2 — TLS 1.3 strongly preferred.",
            "3. Update server configuration (nginx/apache/openssl) with strong cipher suites only.",
            "4. Enable TLS 1.3 which supports only forward-secure cipher suites natively.",
            "5. Run TestSSL to confirm older TLS versions are no longer accepted.",
            "6. Add HSTS headers (Strict-Transport-Security) to prevent downgrade attacks.",
            "7. Submit domain to HSTS preload list for maximum protection.",
        ],
    },
    "WEAK_CIPHER": {
        "title": "Replace Weak Cipher Suites",
        "pqc_alternative": "ChaCha20-Poly1305 or AES-256-GCM",
        "priority": 7,
        "steps": [
            "1. Run TestSSL to enumerate all currently supported cipher suites.",
            "2. Disable NULL, EXPORT, RC4, DES, 3DES, and ANON cipher suites immediately.",
            "3. Disable non-AEAD cipher suites (CBC mode ciphers vulnerable to BEAST/POODLE).",
            "4. Enable only AEAD cipher suites: AES-256-GCM, CHACHA20-POLY1305.",
            "5. Prefer cipher suites with forward secrecy: ECDHE-* or DHE-* prefix.",
            "6. Validate changes with SSLyze and testssl.sh after deployment.",
        ],
    },
    "EXPIRED_CERT": {
        "title": "Renew Expired Certificate — Immediate Action Required",
        "pqc_alternative": "Issue new certificate with PQC-ready CA",
        "priority": 10,
        "steps": [
            "1. URGENT: Immediately renew the expired certificate — this is actively blocking secure connections.",
            "2. Consider using a PQC-ready or hybrid certificate if your CA supports it.",
            "3. Set up automated certificate renewal using Let's Encrypt / ACME protocol.",
            "4. Configure monitoring alerts at 30, 14, and 7 days before expiry.",
            "5. Validate renewed certificate is properly deployed and trusted on all servers.",
        ],
    },
}

# Canonical alias map — maps algorithm name variants to playbook keys
ALGO_ALIAS_MAP = {
    # ECC family
    "ECDSA": "ECC",
    "ECDH":  "ECC",
    "ECDHE": "ECC",
    "EC":    "ECC",
    # DH family
    "DHE":            "DH",
    "FFDHE":          "DH",
    "DIFFIE-HELLMAN": "DH",
    "DIFFIE":         "DH",
    # RSA variants
    "RSA-1024": "RSA",
    "RSA-2048": "RSA",
    "RSA-4096": "RSA",
}


FINDING_TYPE_MAP = {
    "OUTDATED_TLS":          "TLS_OUTDATED",
    "WEAK_CIPHER":           "WEAK_CIPHER",
    "EXPIRED_CERT":          "EXPIRED_CERT",
    "QUANTUM_VULNERABLE_ALGO": "RSA",
    "HNDL_RISK":             "RSA",
    "WEAK_KEY_SIZE":         "RSA",
    "MISSING_PQC":           "RSA",
}


def get_remediation_playbook(finding_type: str, algorithm: str = "") -> Dict[str, Any]:
    """
    Return the best remediation playbook for a given finding type + algorithm.

    Matching order (most specific → least specific):
      1. Direct match on algorithm name (e.g. "RSA" → RSA playbook)
      2. Alias map match       (e.g. "ECDSA" → ECC playbook)
      3. Substring match       (e.g. "RSA-2048" contains "RSA")
      4. Reverse substring     (e.g. "EC" contained in "ECC")
      5. Finding type fallback (e.g. "QUANTUM_VULNERABLE_ALGO" → RSA)
      6. Default RSA playbook
    """
    algo_upper = algorithm.upper().strip() if algorithm else ""

    # 1. Direct key match
    if algo_upper in REMEDIATION_PLAYBOOKS:
        return REMEDIATION_PLAYBOOKS[algo_upper]

    # 2. Alias map
    if algo_upper in ALGO_ALIAS_MAP:
        key = ALGO_ALIAS_MAP[algo_upper]
        if key in REMEDIATION_PLAYBOOKS:
            return REMEDIATION_PLAYBOOKS[key]

    # 3. Substring — algo contains playbook key 
    for key in REMEDIATION_PLAYBOOKS:
        if key in algo_upper:
            return REMEDIATION_PLAYBOOKS[key]

    # 4. Reverse substring — playbook key contains algo 
    for key in REMEDIATION_PLAYBOOKS:
        if algo_upper and algo_upper in key:
            return REMEDIATION_PLAYBOOKS[key]

    # 5. Finding type fallback
    finding_upper = finding_type.upper().strip() if finding_type else ""
    mapped_key = FINDING_TYPE_MAP.get(finding_upper, "RSA")
    return REMEDIATION_PLAYBOOKS.get(mapped_key, REMEDIATION_PLAYBOOKS["RSA"])


def calculate_priority_score(hndl_score: float, asset_criticality: float = 5.0) -> float:
    """
    SRS FR-16: Priority Score = HNDL Score × Asset Criticality / 10
    Returns value 0–10.
    """
    return round(min(hndl_score * asset_criticality / 10.0, 10.0), 2)