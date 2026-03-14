"""
Compliance Mapping Engine
Maps cryptographic findings to NIST PQC, CERT-In, RBI, NIST IR 8547 frameworks.
"""
from typing import List, Dict, Any


COMPLIANCE_RULES = {
    "NIST-PQC": [
        {
            "control_ref": "NIST FIPS 203",
            "title": "Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)",
            "description": "Recommends migration from RSA/ECC to ML-KEM (CRYSTALS-Kyber)",
            "triggers": ["RSA", "ECC", "ECDH", "ECDHE"],
            "severity": "HIGH",
        },
        {
            "control_ref": "NIST FIPS 204",
            "title": "Module-Lattice-Based Digital Signature Algorithm (ML-DSA)",
            "description": "Recommends migration from RSA/DSA/ECDSA to ML-DSA (CRYSTALS-Dilithium)",
            "triggers": ["RSA", "DSA", "ECDSA"],
            "severity": "HIGH",
        },
        {
            "control_ref": "NIST FIPS 205",
            "title": "Stateless Hash-Based Digital Signature Scheme (SLH-DSA)",
            "description": "Alternative PQC digital signature standard (SPHINCS+)",
            "triggers": ["RSA", "DSA", "ECDSA"],
            "severity": "MEDIUM",
        },
    ],
    "NIST-IR-8547": [
        {
            "control_ref": "NIST IR 8547 Sect. 3",
            "title": "PQC Migration Readiness",
            "description": "Organizations should inventory cryptographic assets and assess PQC readiness",
            "triggers": ["*"],
            "severity": "MEDIUM",
        },
        {
            "control_ref": "NIST IR 8547 Sect. 5",
            "title": "Hybrid PQC Deployment",
            "description": "Recommends hybrid classical-PQC schemes during transition",
            "triggers": ["RSA", "ECC", "DH", "DHE"],
            "severity": "HIGH",
        },
    ],
    "CERT-IN": [
        {
            "control_ref": "CERT-In Advisory CIAD-2023-0001",
            "title": "TLS Configuration Hardening",
            "description": "Disable TLS 1.0 and TLS 1.1; use TLS 1.2 minimum, prefer TLS 1.3",
            "triggers": ["TLS 1.0", "TLS 1.1", "SSLv3", "SSLv2"],
            "severity": "HIGH",
        },
        {
            "control_ref": "CERT-In PQC Guidance 2024",
            "title": "Post-Quantum Crypto Preparedness",
            "description": "Indian organizations should begin PQC migration for critical infrastructure",
            "triggers": ["RSA", "ECC", "DH"],
            "severity": "CRITICAL",
        },
    ],
    "RBI": [
        {
            "control_ref": "RBI Cybersecurity Framework 4.2",
            "title": "Encryption Standards for Banking",
            "description": "Banks must use strong encryption for all customer data and transactions",
            "triggers": ["DES", "3DES", "RC4", "MD5"],
            "severity": "CRITICAL",
        },
        {
            "control_ref": "RBI Master Direction IT Framework 2023",
            "title": "Quantum Risk Preparedness for Banks",
            "description": "Banks should assess quantum computing risks to existing cryptographic systems",
            "triggers": ["RSA", "ECC", "DHE"],
            "severity": "HIGH",
        },
    ],
}


def map_finding_to_compliance(algorithm: str, tls_version: str = "", finding_type: str = "") -> List[Dict[str, Any]]:
    """
    Given an algorithm/TLS version, return all compliance framework violations.
    """
    violations = []
    algo_upper = algorithm.upper() if algorithm else ""
    tls_upper = tls_version.upper() if tls_version else ""

    for framework, rules in COMPLIANCE_RULES.items():
        for rule in rules:
            triggered = False
            for trigger in rule["triggers"]:
                if trigger == "*":
                    triggered = True
                    break
                if trigger.upper() in algo_upper or trigger.upper() in tls_upper:
                    triggered = True
                    break
            if triggered:
                violations.append({
                    "framework": framework,
                    "control_ref": rule["control_ref"],
                    "title": rule["title"],
                    "description": rule["description"],
                    "severity": rule["severity"],
                    "status": "NON_COMPLIANT",
                })

    return violations


def get_compliance_summary(findings: List[Dict]) -> Dict[str, Any]:
    """Aggregate compliance status across all findings."""
    framework_counts = {fw: {"compliant": 0, "non_compliant": 0} for fw in COMPLIANCE_RULES}

    for finding in findings:
        for tag in finding.get("compliance_tags", []):
            fw = tag.get("framework")
            if fw in framework_counts:
                if tag.get("status") == "NON_COMPLIANT":
                    framework_counts[fw]["non_compliant"] += 1
                else:
                    framework_counts[fw]["compliant"] += 1

    return framework_counts
