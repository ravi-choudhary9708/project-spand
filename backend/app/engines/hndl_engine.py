"""
HNDL (Harvest Now Decrypt Later) Risk Score Engine
Formula from SRS FR-09:
  HNDL Score (0–10) = (Algorithm Vulnerability Score × 0.40)
                    + (Key Size Risk Score × 0.20)
                    + (Data Sensitivity Weight × 0.30)
                    + (Certificate Expiry Risk × 0.10)
"""
from datetime import datetime
from typing import Optional


# Quantum vulnerability scores for algorithms (0-10)
ALGORITHM_VULNERABILITY_MAP = {
    # High risk - broken by quantum
    "RSA": 9.5,
    "RSA-1024": 10.0,
    "RSA-2048": 9.0,
    "RSA-4096": 7.5,
    "ECC": 9.0,
    "ECDSA": 9.0,
    "ECDH": 9.0,
    "ECDHE": 8.5,
    "DHE": 8.0,
    "DH": 8.5,
    "DSA": 9.0,
    # Medium risk
    "AES-128": 3.0,
    "AES-256": 1.0,  # Quantum safe (Grover's halves security)
    "3DES": 6.0,
    "DES": 9.5,
    # Low/no risk (PQC)
    "CRYSTALS-KYBER": 0.5,
    "CRYSTALS-DILITHIUM": 0.5,
    "FALCON": 0.5,
    "SPHINCS+": 0.5,
    "KYBER": 0.5,
}

# Key size risk scores (higher = more risky)
KEY_SIZE_RISK_MAP = {
    # RSA
    512: 10.0,
    1024: 9.0,
    2048: 7.0,
    3072: 5.0,
    4096: 3.0,
    # ECC
    128: 9.0,
    192: 7.0,
    256: 5.0,
    384: 3.0,
    521: 1.5,
}


def get_algorithm_vulnerability_score(algorithm: str) -> float:
    if not algorithm:
        return 5.0
    algo_upper = algorithm.upper()
    for key, score in ALGORITHM_VULNERABILITY_MAP.items():
        if key in algo_upper:
            return score
    return 5.0  # Unknown = medium risk


def get_key_size_risk(key_size: Optional[int], algorithm: str = "") -> float:
    if not key_size:
        return 5.0
    # Find closest key size
    sizes = sorted(KEY_SIZE_RISK_MAP.keys())
    for size in sizes:
        if key_size <= size:
            return KEY_SIZE_RISK_MAP[size]
    return 1.0  # Very large key = low risk


def get_certificate_expiry_risk(expires_at: Optional[datetime]) -> float:
    if not expires_at:
        return 5.0
    now = datetime.utcnow()
    if expires_at < now:
        return 10.0  # Already expired
    days_remaining = (expires_at - now).days
    if days_remaining < 30:
        return 8.0
    elif days_remaining < 90:
        return 6.0
    elif days_remaining < 180:
        return 4.0
    elif days_remaining < 365:
        return 2.0
    else:
        return 1.0  # Long validity


def calculate_hndl_score(
    algorithm: str,
    key_size: Optional[int] = None,
    data_sensitivity: float = 5.0,  # 0-10, org-provided
    expires_at: Optional[datetime] = None,
) -> float:
    """
    Calculate HNDL risk score using the SRS formula:
    Score = (AlgVuln × 0.40) + (KeySizeRisk × 0.20) + (DataSensitivity × 0.30) + (CertExpiry × 0.10)
    """
    alg_score = get_algorithm_vulnerability_score(algorithm)
    key_score = get_key_size_risk(key_size, algorithm)
    expiry_score = get_certificate_expiry_risk(expires_at)

    hndl = (
        (alg_score * 0.40) +
        (key_score * 0.20) +
        (data_sensitivity * 0.30) +
        (expiry_score * 0.10)
    )
    return round(min(max(hndl, 0.0), 10.0), 2)


def is_quantum_vulnerable(algorithm: str) -> bool:
    score = get_algorithm_vulnerability_score(algorithm)
    return score >= 6.0


def get_pqc_readiness_label(hndl_score: float) -> str:
    if hndl_score <= 2.0:
        return "Quantum Safe"
    elif hndl_score <= 4.5:
        return "Partially Safe"
    elif hndl_score <= 7.5:
        return "Vulnerable"
    else:
        return "Critical Risk"
