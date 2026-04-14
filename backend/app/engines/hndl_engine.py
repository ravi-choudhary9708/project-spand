"""
HNDL v2 — Harvest Now Decrypt Later Risk Score Engine
======================================================

Formula:
  HNDL_final = min(10.0, BCS × W_sensitivity × M_shelf × M_pfs × M_tls_version)

Where:
  BCS = (AlgoVuln × 0.50) + (KeySizeRisk × 0.20) + (TLSRisk × 0.20) + (ExpiryRisk × 0.10)

  W_sensitivity  : Data sensitivity weight   (0.8 → 1.5)
  M_shelf        : Data shelf life multiplier (0.2 → 1.0)
  M_pfs          : Perfect Forward Secrecy    (0.85 if ECDHE, 1.0 if static RSA)
  M_tls_version  : TLS version penalty        (0.6 → 1.15)

PQC Kill Switch: if algorithm is ML-KEM / ML-DSA / SLH-DSA → score = 0.5, bypass all math.
"""

from datetime import datetime
from typing import Optional, Tuple, Dict, List


# ─────────────────────────────────────────────────────────────────
# ALGORITHM VULNERABILITY SCORES  (0–10)
# ─────────────────────────────────────────────────────────────────

ALGORITHM_VULNERABILITY_MAP: Dict[str, float] = {
    # ── Fully quantum-broken (Shor's algorithm) ──────────────────
    "RSA":       9.5,
    "RSA-1024":  10.0,
    "RSA-2048":  9.0,
    "RSA-4096":  7.5,
    "ECC":       9.0,
    "ECDSA":     9.0,
    "ECDH":      9.0,
    "ECDHE":     8.5,   # key exchange — but cert is still classical
    "DHE":       8.0,
    "DH":        8.5,
    "DSA":       9.0,

    # ── Classically weak (not quantum-specific) ───────────────────
    "DES":       9.5,
    "3DES":      6.0,
    "RC4":       8.5,
    "MD5":       7.0,

    # ── Symmetric (Grover halves security, not catastrophic) ──────
    "AES-128":   3.0,
    "AES-256":   1.0,
    "CHACHA20":  1.0,

    # ── Hybrid / transitional ─────────────────────────────────────
    "Ed25519":   1.5,   # not quantum-safe but much stronger than RSA
    "Ed448":     1.5,

    # ── NIST PQC standards — Kill Switch candidates ───────────────
    "ML-KEM":            0.0,   # FIPS 203 (Kyber)
    "ML-DSA":            0.0,   # FIPS 204 (Dilithium)
    "SLH-DSA":           0.0,   # FIPS 205 (SPHINCS+)
    "CRYSTALS-KYBER":    0.0,
    "CRYSTALS-DILITHIUM":0.0,
    "FALCON":            0.5,   # Round 3 alternate — not yet FIPS
    "SPHINCS+":          0.5,
    "KYBER":             0.0,
    "DILITHIUM":         0.0,
}

# Algorithms that trigger the PQC Kill Switch → override score = 0.5
_PQC_KILL_SWITCH_ALGOS = {
    "ML-KEM", "ML-DSA", "SLH-DSA",
    "CRYSTALS-KYBER", "CRYSTALS-DILITHIUM",
    "KYBER", "DILITHIUM",
    "FALCON", "SPHINCS+",
}

# ─────────────────────────────────────────────────────────────────
# KEY SIZE RISK  (0–10)
# ─────────────────────────────────────────────────────────────────

KEY_SIZE_RISK_MAP: Dict[int, float] = {
    # RSA / DH
    512:  10.0,
    1024:  9.0,
    2048:  7.0,
    3072:  5.0,
    4096:  3.0,
    # ECC
    128:   9.0,
    192:   7.0,
    256:   5.0,
    384:   3.0,
    521:   1.5,
}

# ─────────────────────────────────────────────────────────────────
# TLS VERSION RISK  (0–10)
# Used in BCS — raw risk contribution
# ─────────────────────────────────────────────────────────────────

TLS_VERSION_RISK_MAP: Dict[str, float] = {
    "SSLv2":   10.0,
    "SSLv3":   10.0,
    "TLS 1.0":  9.0,
    "TLSv1":    9.0,
    "TLS 1.1":  8.0,
    "TLSv1.1":  8.0,
    "TLS 1.2":  4.0,
    "TLSv1.2":  4.0,
    "TLS 1.3":  1.0,
    "TLSv1.3":  1.0,
}

# ─────────────────────────────────────────────────────────────────
# TLS VERSION MULTIPLIER  M_tls_version
# Separate from the risk score — this multiplies the final BCS.
# Bad TLS amplifies the overall risk; good TLS slightly reduces it.
# ─────────────────────────────────────────────────────────────────

TLS_VERSION_MULTIPLIER_MAP: Dict[str, float] = {
    "SSLv2":   1.30,   # severely amplifies risk
    "SSLv3":   1.25,
    "TLS 1.0": 1.20,
    "TLSv1":   1.20,
    "TLS 1.1": 1.15,
    "TLSv1.1": 1.15,
    "TLS 1.2": 1.00,   # neutral baseline
    "TLSv1.2": 1.00,
    "TLS 1.3": 0.85,   # modern TLS — reduces overall risk slightly
    "TLSv1.3": 0.85,
}

# ─────────────────────────────────────────────────────────────────
# DATA SENSITIVITY WEIGHT  W_sensitivity
# ─────────────────────────────────────────────────────────────────

# Maps domain keyword → sensitivity weight
# Weight > 1.0 amplifies risk; < 1.0 reduces it
_SENSITIVITY_RULES: List[Tuple[List[str], float]] = [
    # Critical financial infrastructure
    (["netbanking", "cbdc", "swift", "rtgs", "neft", "vault", "hsmapi"], 1.50),
    # Payment / transaction flows
    (["payment", "transaction", "payroll", "checkout", "billing"],        1.45),
    # Authentication & identity
    (["vpn", "auth", "login", "idp", "sso", "mfa", "iam", "secure"],     1.40),
    # Credit / lending data
    (["credit", "loan", "debit", "creditcard", "mortgage"],               1.35),
    # API gateways (high data volume)
    (["api", "apim", "gateway", "graphql", "rest", "bbps", "upi"],       1.20),
    # Mail infrastructure
    (["mail", "smtp", "imap", "pop3"],                                    1.10),
    # Standard web
    (["www", "web", "portal", "app"],                                     1.00),
    # Dev / staging (lower sensitivity)
    (["dev", "staging", "test", "uat", "sandbox", "demo"],               0.90),
    # Static / CDN assets (lowest sensitivity)
    (["cdn", "static", "assets", "img", "images", "media", "fonts"],     0.80),
]


def get_sensitivity_weight(domain: str) -> float:
    """
    Return W_sensitivity for a domain by matching keywords.
    Uses the highest-priority match (first rule wins).
    """
    d = domain.lower()
    for keywords, weight in _SENSITIVITY_RULES:
        # Exact subdomain token match — avoids "pay" matching "display"
        for kw in keywords:
            parts = d.replace("-", ".").replace("_", ".").split(".")
            if kw in parts or any(p.startswith(kw) for p in parts):
                return weight
    return 1.00  # neutral default


# ─────────────────────────────────────────────────────────────────
# DATA SHELF LIFE MULTIPLIER  M_shelf
# ─────────────────────────────────────────────────────────────────

# Maps service category / domain keyword → shelf life multiplier
# Ephemeral data (OTPs, streaming) = near zero; long-term storage = 1.0
_SHELF_LIFE_RULES: List[Tuple[List[str], float]] = [
    # Ephemeral — data worthless in minutes/hours
    (["otp", "captcha", "nonce", "totp", "2fa"],                          0.20),
    # Short-lived sessions
    (["session", "token", "refresh", "websocket", "ws", "stream"],        0.40),
    # Transactional — matters for days/weeks
    (["payment", "transaction", "checkout", "transfer"],                  0.70),
    # Operational — matters for months
    (["api", "gateway", "service", "internal"],                           0.85),
    # PII / identity — matters for years (regulatory retention)
    (["kyc", "aadhaar", "pan", "passport", "identity", "profile"],       1.00),
    # Long-term financial records
    (["netbanking", "loan", "credit", "mortgage", "vault", "archive"],   1.00),
    # Mail — mixed but generally important
    (["mail", "smtp", "imap"],                                            0.90),
    # Static assets — content is public anyway
    (["cdn", "static", "assets", "img", "media"],                        0.50),
]


def get_shelf_life_multiplier(domain: str, service_category: str = "") -> float:
    """
    Return M_shelf by matching domain and service category keywords.
    Lowest multiplier wins (most conservative / ephemeral classification).
    """
    text = (domain + "." + service_category).lower()
    parts = set(text.replace("-", ".").replace("_", ".").split("."))

    best = 1.0  # default — assume long-lived
    for keywords, multiplier in _SHELF_LIFE_RULES:
        for kw in keywords:
            if kw in parts or any(p.startswith(kw) for p in parts):
                best = min(best, multiplier)  # take lowest (most conservative)
    return best


# ─────────────────────────────────────────────────────────────────
# PFS MULTIPLIER  M_pfs
# ─────────────────────────────────────────────────────────────────

def get_pfs_multiplier(cipher_suite: Optional[str]) -> float:
    """
    Return M_pfs based on the negotiated cipher suite.

    ECDHE / DHE = Perfect Forward Secrecy → 0.85 (reduces risk)
    Static RSA key exchange → 1.0 (no PFS benefit)
    TLS 1.3 always uses ephemeral key exchange → 0.85

    PFS means captured traffic cannot be retroactively decrypted
    even after the long-term private key is compromised — this
    directly reduces the HNDL threat model.
    """
    if not cipher_suite:
        return 1.0  # unknown — assume worst case

    cu = cipher_suite.upper()

    # TLS 1.3 cipher suites always use ephemeral key exchange
    if cu.startswith("TLS_AES_") or cu.startswith("TLS_CHACHA20_"):
        return 0.85

    # Explicit ECDHE or DHE
    if "ECDHE" in cu or "DHE" in cu:
        return 0.85

    # Static RSA key exchange — no PFS
    return 1.0


# ─────────────────────────────────────────────────────────────────
# COMPONENT SCORERS
# ─────────────────────────────────────────────────────────────────

def get_algorithm_vulnerability_score(algorithm: str) -> float:
    """Return raw algorithm vulnerability score (0–10)."""
    if not algorithm:
        return 5.0
    algo_upper = algorithm.upper()
    # Exact match first
    if algo_upper in ALGORITHM_VULNERABILITY_MAP:
        return ALGORITHM_VULNERABILITY_MAP[algo_upper]
    # Substring match (e.g. "RSA-2048" → "RSA")
    for key, score in ALGORITHM_VULNERABILITY_MAP.items():
        if key in algo_upper:
            return score
    return 5.0  # unknown → medium risk


def get_key_size_risk(key_size: Optional[int], algorithm: str = "") -> float:
    """Return key size risk score (0–10)."""
    if not key_size:
        return 5.0
    sizes = sorted(KEY_SIZE_RISK_MAP.keys())
    for size in sizes:
        if key_size <= size:
            return KEY_SIZE_RISK_MAP[size]
    return 1.0  # very large key → low risk


def get_tls_version_risk(tls_version: Optional[str]) -> float:
    """Return TLS version risk contribution for BCS (0–10)."""
    if not tls_version:
        return 5.0
    return TLS_VERSION_RISK_MAP.get(tls_version, 5.0)


def get_tls_version_multiplier(tls_version: Optional[str]) -> float:
    """Return M_tls_version multiplier (0.85–1.30)."""
    if not tls_version:
        return 1.0  # unknown → neutral
    return TLS_VERSION_MULTIPLIER_MAP.get(tls_version, 1.0)


def get_certificate_expiry_risk(expires_at: Optional[datetime]) -> float:
    """Return certificate expiry risk (0–10)."""
    if not expires_at:
        return 5.0
    now = datetime.utcnow()
    if expires_at < now:
        return 10.0  # already expired
    days = (expires_at - now).days
    if days < 30:   return 8.0
    if days < 90:   return 6.0
    if days < 180:  return 4.0
    if days < 365:  return 2.0
    return 1.0


def is_pqc_kill_switch(algorithm: str) -> bool:
    """Return True if algorithm is a NIST-approved PQC standard."""
    if not algorithm:
        return False
    return algorithm.upper() in _PQC_KILL_SWITCH_ALGOS


# ─────────────────────────────────────────────────────────────────
# MAIN SCORING FUNCTION
# ─────────────────────────────────────────────────────────────────

def calculate_hndl_score(
    algorithm: str,
    key_size:        Optional[int]      = None,
    domain:          str                = "",
    expires_at:      Optional[datetime] = None,
    tls_version:     Optional[str]      = None,
    cipher_suite:    Optional[str]      = None,
    service_category:str                = "",
    # Legacy compatibility — data_sensitivity float still accepted
    # but ignored if domain is provided (domain-based weight is used)
    data_sensitivity:float              = 5.0,
) -> Tuple[float, Dict[str, float]]:
    """
    Calculate HNDL v2 risk score.

    HNDL_final = min(10.0, BCS × W_sensitivity × M_shelf × M_pfs × M_tls_version)

    BCS = (AlgoVuln×0.50) + (KeySizeRisk×0.20) + (TLSRisk×0.20) + (ExpiryRisk×0.10)

    Returns:
        (hndl_score, breakdown_dict)
    """
    # ── PQC Kill Switch ───────────────────────────────────────────
    if is_pqc_kill_switch(algorithm):
        return 0.5, {
            "algorithm_risk":    0.0,
            "key_size_risk":     0.0,
            "tls_version_risk":  0.0,
            "expiry_risk":       0.0,
            "bcs":               0.0,
            "w_sensitivity":     1.0,
            "m_shelf":           1.0,
            "m_pfs":             1.0,
            "m_tls_version":     1.0,
            "pqc_kill_switch":   True,
            "note":              f"PQC algorithm {algorithm} — kill switch applied",
        }

    # ── Component scores ──────────────────────────────────────────
    algo_score   = get_algorithm_vulnerability_score(algorithm)
    key_score    = get_key_size_risk(key_size, algorithm)
    tls_risk     = get_tls_version_risk(tls_version)
    expiry_score = get_certificate_expiry_risk(expires_at)

    # ── Base Cryptographic Score ──────────────────────────────────
    bcs = (
        (algo_score   * 0.50) +
        (key_score    * 0.20) +
        (tls_risk     * 0.20) +
        (expiry_score * 0.10)
    )

    # ── Context Multipliers ───────────────────────────────────────
    # W_sensitivity: domain-keyword based if domain provided,
    # else fall back to legacy float → mapped to weight
    if domain:
        w_sensitivity = get_sensitivity_weight(domain)
    else:
        # Legacy compatibility: map 0–10 float to 0.8–1.5 range
        w_sensitivity = 0.8 + (data_sensitivity / 10.0) * 0.7

    m_shelf      = get_shelf_life_multiplier(domain, service_category)
    m_pfs        = get_pfs_multiplier(cipher_suite)
    m_tls_ver    = get_tls_version_multiplier(tls_version)

    # ── Final score ───────────────────────────────────────────────
    raw = bcs * w_sensitivity * m_shelf * m_pfs * m_tls_ver
    final = round(min(max(raw, 0.0), 10.0), 2)

    breakdown = {
        # Raw component scores (pre-weight)
        "algorithm_risk":    round(algo_score,   2),
        "key_size_risk":     round(key_score,    2),
        "tls_version_risk":  round(tls_risk,     2),
        "expiry_risk":       round(expiry_score, 2),
        # Intermediate
        "bcs":               round(bcs,          2),
        # Multipliers
        "w_sensitivity":     round(w_sensitivity,2),
        "m_shelf":           round(m_shelf,      2),
        "m_pfs":             round(m_pfs,        2),
        "m_tls_version":     round(m_tls_ver,    2),
        # Meta
        "pqc_kill_switch":   False,
    }

    return final, breakdown


# ─────────────────────────────────────────────────────────────────
# CONVENIENCE FUNCTIONS  (unchanged API for scan_tasks.py)
# ─────────────────────────────────────────────────────────────────

def is_quantum_vulnerable(algorithm: str) -> bool:
    return get_algorithm_vulnerability_score(algorithm) >= 6.0


def is_pqc_ready(algorithm: str) -> bool:
    if not algorithm or algorithm.upper() == "UNKNOWN":
        return False
    return get_algorithm_vulnerability_score(algorithm) <= 1.5


def get_pqc_readiness_label(hndl_score: float) -> str:
    if hndl_score <= 1.0:  return "Quantum Safe"
    if hndl_score <= 3.5:  return "Partially Safe"
    if hndl_score <= 6.5:  return "Vulnerable"
    return "Critical Risk"
