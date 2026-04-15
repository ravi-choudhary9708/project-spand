"""
AI-Assisted Remediation Engine
Generates step-by-step PQC migration playbooks for cryptographic vulnerabilities.
Place at: backend/app/engines/ai_remediation.py
"""
from typing import Dict, Any, Optional
import json
import requests
import logging
import re

from app.config import settings

logger = logging.getLogger(__name__)

HF_API_URL = "https://router.huggingface.co/v1/chat/completions"


REMEDIATION_PLAYBOOKS = {
    "RSA": {
        "title": "Quantum-Resistant Migration for RSA Infrastructure",
        "priority": 9,
        "pqc_alternative": "ML-KEM (FIPS 203) / ML-DSA (FIPS 204)",
        "steps": [
            "1. Inventory and tag all RSA keys and X.509 certificates.",
            "2. Identify priority assets with HNDL scores > 7.0.",
            "3. Prepare CA infrastructure for Hybrid post-quantum/classical certificates.",
            "4. Update client/server libraries to support ML-KEM and ML-DSA.",
            "5. Implement X25519Kyber768 hybrid key exchange (highly recommended).",
            "6. Transition production traffic to hybrid mode before full PQC rollout.",
            "7. Revoke legacy RSA credentials after multi-environment validation."
        ],
        "detailed_report": "CRITICAL RISK: RSA is mathematically vulnerable to Shor's algorithm. For a domain like {domain}, this means an adversary capturing traffic today can decrypt it once a CRQC (Cryptographically Relevant Quantum Computer) is available. \n\nMIGRATION GUIDANCE:\n- Immediate Action: Deploy Hybrid TLS 1.3. This combines classical ECDH (X25519) with post-quantum ML-KEM (Kyber). \n- Technical Snippet (Nginx/OpenSSL): Use OpenSSL 3.2+ which supports Kyber providers. \n- Compliance: Align with NIST FIPS 203 and 204 draft guidance. \n- Resilience: Focus on crypto-agility by ensuring your software stack can swap algorithms without code rewrites."
    },
    "ECC": {
        "title": "Post-Quantum Hardening for Elliptic Curve Assets",
        "pqc_alternative": "ML-KEM-768 / ML-DSA-65",
        "priority": 8,
        "steps": [
            "1. Evaluate current ECC curves (p256, p384, Ed25519) for quantum exposure.",
            "2. Map dependencies for PQC-compatible HSMs and hardware modules.",
            "3. Transition to ML-DSA (FIPS 204) for digital signature validation.",
            "4. Upgrade TLS termination endpoints to support PQC-enabled KEMs.",
            "5. Monitor performance impact of larger PQC key/ciphertext sizes.",
            "6. Phase out classical-only EC certificates in favor of PQC-hybrid."
        ],
        "detailed_report": "ECC analysis for {domain}: While ECC provides superior classical performance, it offers zero quantum resistance. All NIST-recommended PQC algorithms (ML-KEM, ML-DSA) are significantly larger in size. \n\nENGINEERING ADVICE:\n- Network Impact: Anticipate increased handshake latency due to larger PQC key exchanges. \n- Algorithm choice: Use ML-KEM (Kyber) for sub-millisecond key encapsulation. \n- Storage: Update database schemas that store public keys to accommodate variable lengths of PQC byte arrays."
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


def get_remediation_playbook(finding_type: str, algorithm: str = "", domain: str = "") -> Dict[str, Any]:
    """
    Returns a static remediation playbook based on the finding type or algorithm.

    Matching order (most specific → least specific):
      1. Direct match on algorithm name (e.g. "RSA" → RSA playbook)
      2. Alias map match       (e.g. "ECDSA" → ECC playbook)
      3. Substring match       (e.g. "RSA-2048" contains "RSA")
      4. Reverse substring     (e.g. "EC" contained in "ECC")
      5. Finding type fallback (e.g. "QUANTUM_VULNERABLE_ALGO" → RSA)
      6. Default RSA playbook
    """
    algo_upper = algorithm.upper().strip() if algorithm else ""
    playbook = None

    # 1. Direct key match
    if algo_upper in REMEDIATION_PLAYBOOKS:
        playbook = REMEDIATION_PLAYBOOKS[algo_upper]

    # 2. Alias map
    if not playbook and algo_upper in ALGO_ALIAS_MAP:
        key = ALGO_ALIAS_MAP[algo_upper]
        if key in REMEDIATION_PLAYBOOKS:
            playbook = REMEDIATION_PLAYBOOKS[key]

    # 3. Substring — algo contains playbook key 
    if not playbook:
        for key in REMEDIATION_PLAYBOOKS:
            if key in algo_upper:
                playbook = REMEDIATION_PLAYBOOKS[key]
                break

    # 4. Reverse substring — playbook key contains algo 
    if not playbook:
        for key in REMEDIATION_PLAYBOOKS:
            if algo_upper and algo_upper in key:
                playbook = REMEDIATION_PLAYBOOKS[key]
                break

    if not playbook:
        # 5. Finding type fallback
        finding_upper = finding_type.upper().strip() if finding_type else ""
        mapped_key = FINDING_TYPE_MAP.get(finding_upper, "RSA")
        playbook = REMEDIATION_PLAYBOOKS.get(mapped_key, REMEDIATION_PLAYBOOKS["RSA"])

    # Deep copy and format 
    result = json.loads(json.dumps(playbook))
    if "detailed_report" in result:
        result["detailed_report"] = result["detailed_report"].replace("{domain}", domain)
    return result


def try_ai_call(model: str, headers: dict, system_msg: str, user_msg: str, domain: str) -> Optional[Dict[str, Any]]:
    """Helper to call HF Router with a specific model and robust parsing."""
    try:
        logger.info(f"Attempting AI generation with model: {model}")
        response = requests.post(
            HF_API_URL, 
            headers=headers, 
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": system_msg},
                    {"role": "user", "content": user_msg}
                ],
                "max_tokens": 1024,
                "temperature": 0.2
            }, 
            timeout=25
        )
        
        if response.status_code != 200:
            logger.error(f"HF Router ({model}) returned {response.status_code}: {response.text[:200]}")
            return None
        
        if not response.text:
            logger.error(f"HF Router ({model}) returned 200 OK but EMPTY BODY.")
            return None

        content = response.json()["choices"][0]["message"]["content"]
        
        # REGEX EXTRACTION: Find the first { and the last }
        json_match = re.search(r'\{.*\}', content, re.DOTALL)
        json_str = json_match.group(0) if json_match else content.strip()
            
        # Clean up possible markdown code blocks manually as fallback
        if "```json" in json_str:
            json_str = json_str.split("```json")[-1].split("```")[0]
            
        try:
            return json.loads(json_str.strip())
        except json.JSONDecodeError as jde:
            # V10 REPAIR LOGIC: Handle common unescaped technical content
            logger.warning(f"Initial JSON parse failed for {model}: {str(jde)}. Attempting recovery...")
            
            # 1. Handle unescaped newlines in strings
            repaired = re.sub(r'(?<!\\)\n', '\\\\n', json_str)
            
            # 2. Try to fix missing commas or unescaped inner quotes (Heuristic)
            try:
                return json.loads(repaired.strip())
            except:
                logger.error(f"AUTO-REPAIR FAILED for {model}. RAW CONTENT START:\n{content}\nRAW CONTENT END")
                raise jde
            
    except Exception as e:
        logger.warning(f"AI Call failed for model {model}: {str(e)}")
        return None


def generate_ai_playbook_on_demand(finding_type: str, algorithm: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Final resilience path for AI remediation. Tries primary and secondary models.
    """
    context = context or {}
    domain_name = context.get('domain', 'the affected system')
    severity = context.get('severity', 'High')
    title = context.get('finding_title', 'Cryptographic Vulnerability')
    desc = context.get('description', 'A cryptographic weakness was detected.')
    
    if not settings.HUGGINGFACE_API_KEY:
        return get_remediation_playbook(finding_type, algorithm, domain_name)

    headers = {
        "Authorization": f"Bearer {settings.HUGGINGFACE_API_KEY}",
        "Content-Type": "application/json"
    }

    system_msg = """You are a World-Class Cryptographer and Post-Quantum Security Architect. 
Your goal is to provide deep, engineer-level migration blueprints. 
DO NOT repeat the instructions. DO NOT use generic phrases.
Include exact CLI commands for OpenSSL 3.3 and Nginx/Apache."""
    
    user_msg = f"""CRYPTO-MIGRATION TASK: {title}
Domain: {domain_name}
Target Algorithm: {algorithm}
Severity: {severity}

Vulnerability Context: RSA/ECC is vulnerable to Shor's algorithm. 

REQUIREMENTS:
1. Generate an 8-step technical execution plan for a Senior DevOps Engineer.
2. Provide a 'detailed_report' that is a DEEP ARCHITECTURAL DIVE. 
3. Include a 'Technical Snippet' section with:
   - OpenSSL 3.3 command to test ML-KEM support.
   - Nginx 'ssl_conf_command Options Groups' example for hybrid X25519Kyber768.

STRICT FORMAT: Respond in valid JSON ONLY. Double quotes inside strings MUST be escaped.

{{
    "steps": ["Step 1...", "Step 2..."],
    "detailed_report": "### 🛡️ QUANTUM-RESILIENT STRATEGY FOR {domain_name}\\n\\nCritical assessment of {algorithm} indicates... [DetailedTechnicalPlan]..."
}}"""

    # --- DUAL-ENGINE RETRY PATTERN ---
    # Try Qwen 2.5 (High Capability)
    result = try_ai_call("Qwen/Qwen2.5-7B-Instruct", headers, system_msg, user_msg, domain_name)
    
    # If failed, try Llama 3.1 (High Stability)
    if not result:
        logger.info("Retrying with fallback engine: Llama-3.1-8B")
        result = try_ai_call("meta-llama/Llama-3.1-8B-Instruct", headers, system_msg, user_msg, domain_name)

    if result:
        return result

    # Final fallback to static guidance
    logger.warning("All AI models failed or returned empty data. Reverting to expert static blueprints.")
    return get_remediation_playbook(finding_type, algorithm, domain_name)


def calculate_priority_score(hndl_score: float, asset_criticality: float = 5.0) -> float:
    """
    SRS FR-16: Priority Score = HNDL Score × Asset Criticality / 10
    Returns value 0–10.
    """
    return round(min(hndl_score * asset_criticality / 10.0, 10.0), 2)