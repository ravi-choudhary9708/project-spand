"""
CycloneDX CBOM Generator
Generates Cryptographic Bill of Materials in CycloneDX 1.4 JSON format.
"""
import uuid
from datetime import datetime
from typing import List, Dict, Any


def generate_cbom(scan_job: Dict, assets: List[Dict]) -> Dict[str, Any]:
    """
    Generate a CycloneDX-format CBOM for a completed scan.
    """
    cbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": f"urn:uuid:{str(uuid.uuid4())}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "tools": [
                {
                    "vendor": "Team Spand",
                    "name": "Quantum-Proof Systems Scanner",
                    "version": "1.0.0",
                }
            ],
            "component": {
                "type": "application",
                "name": scan_job.get("org_name", "Unknown Organization"),
                "bom-ref": f"org-{scan_job.get('scan_id', 'unknown')}",
            },
        },
        "components": [],
        "dependencies": [],
        "vulnerabilities": [],
        "cryptoProperties": {
            "totalAssets": len(assets),
            "quantumVulnerableCount": 0,
            "pqcReadyCount": 0,
            "overallHndlScore": 0.0,
        },
    }

    total_hndl = 0.0
    quantum_vuln_count = 0
    pqc_ready_count = 0

    for asset in assets:
        # Asset component
        bom_ref = f"asset-{asset.get('asset_id', str(uuid.uuid4()))}"
        component = {
            "type": "library",
            "bom-ref": bom_ref,
            "name": asset.get("domain", "unknown"),
            "description": f"Service: {asset.get('service_category', 'unknown')} | Protocol: {asset.get('protocol', 'unknown')}",
            "cryptoProperties": {
                "assetType": "protocol",
                "algorithmProperties": [],
                "certificateProperties": {},
                "relatedCryptoMaterialProperties": {
                    "type": "asset",
                    "hndlScore": asset.get("hndl_score", 0.0),
                    "isPQC": asset.get("is_pqc", False),
                    "pqcReadiness": asset.get("pqc_readiness", "Vulnerable"),
                    "isCDN": asset.get("is_cdn", False),
                    "openPorts": asset.get("open_ports", []),
                    "resolvedIPs": asset.get("resolved_ips", []),
                },
            },
        }

        # Add cipher suites
        for cipher in asset.get("cipher_suites", []):
            component["cryptoProperties"]["algorithmProperties"].append({
                "primitive": "cipher",
                "parameterSetIdentifier": cipher.get("name", "unknown"),
                "executionEnvironment": "hardware-unknown",
                "implementationPlatform": "unknown",
                "certificationLevel": ["other"],
                "mode": "cbc",
                "tlsVersion": cipher.get("tls_version", ""),
                "keyExchange": cipher.get("key_exchange", ""),
                "quantumRisk": cipher.get("quantum_risk", 0.0),
                "quantumVulnerable": cipher.get("is_quantum_vulnerable", False),
            })

        # Add certificate
        for cert in asset.get("certificates", []):
            component["cryptoProperties"]["certificateProperties"] = {
                "subjectName": cert.get("subject", ""),
                "issuerName": cert.get("issuer", ""),
                "notValidAfter": cert.get("expires_at", ""),
                "signatureAlgorithmRef": cert.get("algorithm", ""),
                "keySize": cert.get("key_size", 0),
                "hndlScore": cert.get("hndl_score", 0.0),
                "isPQC": cert.get("is_pqc", False),
            }

        cbom["components"].append(component)

        # Aggregates
        hndl = asset.get("hndl_score", 0.0)
        total_hndl += hndl
        if not asset.get("is_pqc", False):
            quantum_vuln_count += 1
        else:
            pqc_ready_count += 1

        # Vulnerabilities from findings
        for finding in asset.get("findings", []):
            if finding.get("quantum_risk", 0.0) > 0:
                vuln = {
                    "bom-ref": f"vuln-{finding.get('finding_id', str(uuid.uuid4()))}",
                    "id": finding.get("cwe_id", "CWE-326"),
                    "source": {
                        "name": "Quantum-Proof Systems Scanner",
                        "url": "https://github.com/team-spand/qps-scanner",
                    },
                    "ratings": [
                        {
                            "source": {"name": "HNDL Score"},
                            "score": finding.get("hndl_score", 0.0),
                            "severity": finding.get("severity", "medium").lower(),
                            "method": "HNDL",
                            "vector": f"HNDL/{finding.get('type', 'unknown')}",
                        }
                    ],
                    "description": finding.get("description", ""),
                    "recommendation": finding.get("remediation", ""),
                    "affects": [{"ref": bom_ref}],
                }
                cbom["vulnerabilities"].append(vuln)

    # Update aggregate crypto properties
    cbom["cryptoProperties"]["quantumVulnerableCount"] = quantum_vuln_count
    cbom["cryptoProperties"]["pqcReadyCount"] = pqc_ready_count
    cbom["cryptoProperties"]["overallHndlScore"] = (
        round(total_hndl / len(assets), 2) if assets else 0.0
    )

    return cbom
