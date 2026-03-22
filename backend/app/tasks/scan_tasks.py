"""
Celery Scan Tasks - runs the full scan pipeline asynchronously
"""
import uuid
from datetime import datetime
from celery import shared_task
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models.models import (
    ScanJob, Asset, Certificate, CipherSuite, Finding,
    Remediation, CBOM, ComplianceTag,
    ScanStatus, ProtocolType, FindingType, PQCReadiness
)
from app.scanning.scanner import scan_asset, run_subfinder
from app.engines.hndl_engine import calculate_hndl_score, is_quantum_vulnerable, get_pqc_readiness_label
from app.engines.compliance_engine import map_finding_to_compliance
from app.engines.ai_remediation import get_remediation_playbook
from app.engines.cbom_generator import generate_cbom
import logging

logger = logging.getLogger(__name__)


@shared_task(bind=True, name="app.tasks.scan_tasks.run_full_scan", max_retries=2)
def run_full_scan(self, scan_id: str):

    db: Session = SessionLocal()

    try:
        scan_job = db.query(ScanJob).filter(ScanJob.scan_id == scan_id).first()

        if not scan_job:
            logger.error(f"ScanJob {scan_id} not found")
            return

        scan_job.status = ScanStatus.RUNNING
        scan_job.started_at = datetime.utcnow()
        db.commit()

        targets = scan_job.target_assets or []
        all_domains = list(targets)

        self.update_state(state="PROGRESS", meta={"progress": 5, "step": "Asset Discovery"})

        expanded_domains = []

        for target in targets:

            if not any(c.isdigit() for c in target.split(".")[0]):
                subdomains = run_subfinder(target)
                expanded_domains.extend(subdomains)

            else:
                expanded_domains.append(target)

        all_domains = list(set(expanded_domains))

        total = len(all_domains)

        logger.info(f"Scanning {total} assets for scan {scan_id}")

        processed_assets = []

        for i, domain in enumerate(all_domains):

            progress = int(10 + (i / total) * 75)

            self.update_state(
                state="PROGRESS",
                meta={"progress": progress, "step": f"Scanning {domain}"}
            )

            scan_job.progress = progress
            db.commit()

            try:

                scan_data = scan_asset(domain)

                asset = Asset(
                    asset_id=str(uuid.uuid4()),
                    scan_id=scan_id,
                    domain=domain,
                    resolved_ips=scan_data.get("resolved_ips", []),
                    protocol=_map_protocol(scan_data.get("protocol", "UNKNOWN")),
                    is_cdn=scan_data.get("is_cdn", False),
                    open_ports=scan_data.get("open_ports", []),
                    service_category=_get_service_category(scan_data.get("protocol", "")),
                )

                db.add(asset)
                db.flush()

                tls_data = scan_data.get("tls_data", {})

                main_algorithm = "RSA"
                main_key_size = 2048
                expires_at = None

                # NEW: infer sensitivity
                sensitivity = _get_data_sensitivity(domain)

                for cert_data in scan_data.get("certificates", []):

                    subject = cert_data.get("subject", {})
                    issuer = cert_data.get("issuer", {})

                    algorithm = cert_data.get("algorithm", "RSA")
                    key_size = cert_data.get("key_size", 2048)

                    not_after_str = cert_data.get("notAfter", "")

                    try:
                        expires_at = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")

                    except Exception:
                        expires_at = None

                    main_algorithm = algorithm or "RSA"
                    main_key_size = key_size or 2048

                    cert_hndl = calculate_hndl_score(
                        main_algorithm,
                        main_key_size,
                        sensitivity,
                        expires_at
                    )

                    cert = Certificate(
                        cert_id=str(uuid.uuid4()),
                        asset_id=asset.asset_id,
                        domain=domain,
                        subject=str(subject.get("commonName", domain)) if isinstance(subject, dict) else domain,
                        issuer=str(issuer.get("organizationName", "Unknown")) if isinstance(issuer, dict) else "Unknown",
                        algorithm=main_algorithm,
                        key_size=main_key_size,
                        hndl_score=cert_hndl,
                        expires_at=expires_at,
                        is_pqc=not is_quantum_vulnerable(main_algorithm),
                    )

                    db.add(cert)

                for suite_data in scan_data.get("cipher_suites", []):

                    suite_name = suite_data.get("name", "")
                    key_exchange = suite_data.get("key_exchange", "RSA")
                    tls_version = suite_data.get("tls_version", "TLS 1.2")

                    quantum_risk = calculate_hndl_score(key_exchange)

                    suite = CipherSuite(
                        suite_id=str(uuid.uuid4()),
                        asset_id=asset.asset_id,
                        name=suite_name,
                        tls_version=tls_version,
                        key_exchange=key_exchange,
                        quantum_risk=quantum_risk,
                        is_quantum_vulnerable=is_quantum_vulnerable(key_exchange),
                        strength="weak" if quantum_risk > 6.0 else "medium" if quantum_risk > 3.0 else "strong",
                    )

                    db.add(suite)

                    if tls_version in ["TLS 1.0", "TLS 1.1", "SSLv3", "SSLv2"]:

                        _create_finding(
                            db,
                            asset.asset_id,
                            FindingType.OUTDATED_TLS,
                            "HIGH",
                            7.5,
                            "CWE-326",
                            f"Outdated TLS Version: {tls_version}",
                            f"The service supports {tls_version} which is deprecated and insecure.",
                            tls_version,
                        )

                asset_hndl = calculate_hndl_score(
                    main_algorithm,
                    main_key_size,
                    sensitivity,
                    expires_at
                )

                asset.hndl_score = asset_hndl

                asset.is_pqc = not is_quantum_vulnerable(main_algorithm)

                pqc_label = get_pqc_readiness_label(asset_hndl)

                asset.pqc_readiness = _map_pqc_readiness(pqc_label)

                if is_quantum_vulnerable(main_algorithm):

                    finding = _create_finding(
                        db,
                        asset.asset_id,
                        FindingType.QUANTUM_VULNERABLE_ALGO,
                        "CRITICAL" if asset_hndl >= 7.5 else "HIGH",
                        asset_hndl,
                        "CWE-327",
                        f"Quantum-Vulnerable Algorithm: {main_algorithm}",
                        f"Algorithm {main_algorithm} is vulnerable to quantum attacks (Shor's algorithm).",
                        main_algorithm,
                    )

                    if finding:

                        playbook = get_remediation_playbook("QUANTUM_VULNERABLE_ALGO", main_algorithm)

                        remediation = Remediation(
                            playbook_id=str(uuid.uuid4()),
                            finding_id=finding.finding_id,
                            priority=playbook.get("priority", 5),
                            steps=playbook.get("steps", []),
                            pqc_alternative=playbook.get("pqc_alternative", ""),
                        )

                        db.add(remediation)

                        violations = map_finding_to_compliance(
                            main_algorithm,
                            tls_data.get("tls_version", "")
                        )

                        for v in violations:

                            tag = ComplianceTag(
                                tag_id=str(uuid.uuid4()),
                                finding_id=finding.finding_id,
                                framework=v["framework"],
                                control_ref=v["control_ref"],
                                status="NON_COMPLIANT",
                                description=v["description"],
                            )

                            db.add(tag)

                db.commit()

                processed_assets.append({
                    "domain": domain,
                    "asset_id": asset.asset_id,
                    "hndl_score": asset_hndl,
                })

            except Exception as e:

                logger.error(f"Error scanning {domain}: {e}")
                db.rollback()
                continue

        self.update_state(state="PROGRESS", meta={"progress": 90, "step": "Generating CBOM"})

        _generate_scan_cbom(db, scan_job, processed_assets)

        scan_job.status = ScanStatus.COMPLETED
        scan_job.completed_at = datetime.utcnow()
        scan_job.progress = 100

        db.commit()

        self.update_state(state="SUCCESS", meta={"progress": 100, "step": "Complete"})

        return {
            "status": "completed",
            "scan_id": scan_id,
            "assets": len(processed_assets)
        }

    except Exception as e:

        logger.error(f"Scan {scan_id} failed: {e}")

        if scan_job:
            scan_job.status = ScanStatus.FAILED
            db.commit()

        raise self.retry(exc=e, countdown=30) if self.request.retries < self.max_retries else None

    finally:
        db.close()


def _create_finding(db, asset_id, finding_type, severity, hndl_score, cwe_id, title, description, algorithm=""):

    try:

        finding = Finding(
            finding_id=str(uuid.uuid4()),
            asset_id=asset_id,
            type=finding_type,
            severity=severity,
            hndl_score=hndl_score,
            cwe_id=cwe_id,
            title=title,
            description=description,
            quantum_risk=hndl_score,
            details={"algorithm": algorithm},
        )

        db.add(finding)
        db.flush()

        return finding

    except Exception as e:

        logger.error(f"Failed to create finding: {e}")
        return None


def _generate_scan_cbom(db, scan_job, processed_assets):

    try:

        # Query full asset data from DB for the CBOM generator
        full_assets = []
        assets = db.query(Asset).filter(Asset.scan_id == scan_job.scan_id).all()

        for asset in assets:
            certs = db.query(Certificate).filter(Certificate.asset_id == asset.asset_id).all()
            suites = db.query(CipherSuite).filter(CipherSuite.asset_id == asset.asset_id).all()
            findings = db.query(Finding).filter(Finding.asset_id == asset.asset_id).all()

            full_assets.append({
                "asset_id": asset.asset_id,
                "domain": asset.domain,
                "hndl_score": asset.hndl_score,
                "is_pqc": asset.is_pqc,
                "pqc_readiness": asset.pqc_readiness.value if asset.pqc_readiness else "Vulnerable",
                "is_cdn": asset.is_cdn,
                "is_waf": asset.is_waf,
                "open_ports": asset.open_ports or [],
                "resolved_ips": asset.resolved_ips or [],
                "protocol": asset.protocol.value if asset.protocol else "UNKNOWN",
                "service_category": asset.service_category,
                "certificates": [
                    {
                        "cert_id": c.cert_id,
                        "subject": c.subject,
                        "issuer": c.issuer,
                        "algorithm": c.algorithm,
                        "key_size": c.key_size,
                        "hndl_score": c.hndl_score,
                        "expires_at": c.expires_at.isoformat() if c.expires_at else None,
                        "is_pqc": c.is_pqc,
                    }
                    for c in certs
                ],
                "cipher_suites": [
                    {
                        "name": s.name,
                        "tls_version": s.tls_version,
                        "key_exchange": s.key_exchange,
                        "quantum_risk": s.quantum_risk,
                        "is_quantum_vulnerable": s.is_quantum_vulnerable,
                    }
                    for s in suites
                ],
                "findings": [
                    {
                        "finding_id": f.finding_id,
                        "type": f.type.value if hasattr(f.type, "value") else f.type,
                        "severity": f.severity,
                        "hndl_score": f.hndl_score,
                        "cwe_id": f.cwe_id,
                        "title": f.title,
                        "description": f.description,
                        "remediation": f.remediation,
                        "quantum_risk": f.quantum_risk,
                    }
                    for f in findings
                ],
            })

        cbom_data = generate_cbom(
            {"scan_id": scan_job.scan_id, "org_name": scan_job.org_name},
            full_assets
        )

        cbom = CBOM(
            cbom_id=str(uuid.uuid4()),
            scan_id=scan_job.scan_id,
            format="CycloneDX",
            content=cbom_data,
        )

        db.add(cbom)
        db.commit()

    except Exception as e:

        logger.error(f"CBOM generation failed: {e}")


def _get_data_sensitivity(domain: str) -> float:

    domain_lower = domain.lower()

    if any(x in domain_lower for x in ['netbanking', 'payment', 'pay', 'transaction']):
        return 10.0

    elif any(x in domain_lower for x in ['vpn', 'remote', 'secure', 'login', 'auth']):
        return 9.0

    elif any(x in domain_lower for x in ['api', 'gateway', 'service']):
        return 7.5

    elif any(x in domain_lower for x in ['mail', 'smtp', 'imap']):
        return 6.0

    elif any(x in domain_lower for x in ['cdn', 'static', 'assets', 'img']):
        return 2.0

    elif any(x in domain_lower for x in ['www', 'web']):
        return 5.0

    return 5.0


def _map_protocol(proto_str: str) -> ProtocolType:

    mapping = {
        "HTTPS": ProtocolType.HTTPS,
        "HTTP": ProtocolType.HTTP,
        "SMTP": ProtocolType.SMTP,
        "IMAP": ProtocolType.IMAP,
        "POP3": ProtocolType.POP3,
        "FTPS": ProtocolType.FTPS,
        "SSH": ProtocolType.SSH,
        "VPN": ProtocolType.VPN,
    }

    return mapping.get(proto_str.upper(), ProtocolType.UNKNOWN)


def _get_service_category(protocol: str) -> str:

    mapping = {
        "HTTPS": "web",
        "HTTP": "web",
        "SMTP": "mail",
        "IMAP": "mail",
        "POP3": "mail",
        "FTPS": "file_transfer",
        "SSH": "remote_access",
        "VPN": "vpn",
    }

    return mapping.get(protocol.upper(), "other")


def _map_pqc_readiness(label: str) -> PQCReadiness:

    mapping = {
        "Quantum Safe": PQCReadiness.QUANTUM_SAFE,
        "Partially Safe": PQCReadiness.PARTIALLY_SAFE,
        "Vulnerable": PQCReadiness.VULNERABLE,
        "Critical Risk": PQCReadiness.CRITICAL,
    }

    return mapping.get(label, PQCReadiness.VULNERABLE)


@shared_task(name="app.tasks.scan_tasks.run_scheduled_rescans")
def run_scheduled_rescans():

    logger.info("Running scheduled rescans...")

    pass