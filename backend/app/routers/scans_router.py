"""
Scans Router — QuantumShield API
"""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import List, Optional
import uuid
import datetime

from ..database import get_db
from ..models.models import (
    ScanJob, ScanStatus, Asset, Finding, ComplianceTag,
    Remediation, Certificate, CipherSuite, CBOM, PQCReadiness, UserRole
)
from ..auth.auth import get_current_user, require_roles
from ..tasks.scan_tasks import run_full_scan
from ..celery_app import celery_app

router = APIRouter(prefix="/api/scans", tags=["scans"])


@router.post("")
def start_scan(
    body: dict,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user=Depends(require_roles(UserRole.ADMIN, UserRole.SECURITY_ANALYST, UserRole.SOC_TEAM))
):
    org_name = body.get("org_name", "").strip()
    target_assets = body.get("target_assets", [])

    if not org_name:
        raise HTTPException(status_code=400, detail="org_name is required")
    if not target_assets:
        raise HTTPException(status_code=400, detail="target_assets is required")

    scan_id = str(uuid.uuid4())
    scan = ScanJob(
        scan_id=scan_id,
        org_name=org_name,
        target_assets=target_assets,
        authorized=body.get("authorized", False),
        status=ScanStatus.PENDING,
        created_by=current_user.id,
        started_at=datetime.datetime.utcnow(),
    )
    db.add(scan)
    db.commit()

    # Dispatch to Celery in the correct queue
    celery_app.send_task("app.tasks.scan_tasks.run_full_scan", args=[scan_id], queue="scans")

    return {"scan_id": scan_id, "status": "PENDING", "message": "Scan queued successfully"}


@router.get("")
def list_scans(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    scans = db.query(ScanJob).order_by(ScanJob.started_at.desc()).limit(50).all()
    result = []
    for s in scans:
        asset_count = db.query(Asset).filter(Asset.scan_id == s.scan_id).count()
        result.append({
            "scan_id":       s.scan_id,
            "org_name":      s.org_name,
            "status":        s.status.value if s.status else "PENDING",
            "progress":      s.progress or 0,
            "asset_count":   asset_count,
            "target_assets": s.target_assets or [],
            "created_at":    s.started_at.isoformat() if s.started_at else None,
            "completed_at":  s.completed_at.isoformat() if s.completed_at else None,
        })
    return result


@router.get("/{scan_id}")
def get_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    scan = db.query(ScanJob).filter(ScanJob.scan_id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    asset_count = db.query(Asset).filter(Asset.scan_id == scan_id).count()
    avg_hndl = db.query(func.avg(Asset.hndl_score)).filter(Asset.scan_id == scan_id).scalar() or 0.0
    quantum_safe = db.query(Asset).filter(
        Asset.scan_id == scan_id,
        Asset.pqc_readiness == PQCReadiness.QUANTUM_SAFE
    ).count()
    pqc_pct = round((quantum_safe / asset_count * 100) if asset_count > 0 else 0, 1)
    critical_findings = 0
    for asset in scan.assets:
        critical_findings += db.query(Finding).filter(
            Finding.asset_id == asset.asset_id,
            Finding.severity == "CRITICAL"
        ).count()

    return {
        "scan_id":           scan.scan_id,
        "org_name":          scan.org_name,
        "status":            scan.status.value if scan.status else "PENDING",
        "progress":          scan.progress or 0,
        "target_assets":     scan.target_assets or [],
        "asset_count":       asset_count,
        "avg_hndl":          round(float(avg_hndl), 2),
        "pqc_ready_pct":     pqc_pct,
        "critical_findings": critical_findings,
        "created_at":        scan.started_at.isoformat() if scan.started_at else None,
        "completed_at":      scan.completed_at.isoformat() if scan.completed_at else None,
    }


# ── GET /scans/{scan_id}/findings — All findings with compliance + remediation
@router.get("/{scan_id}/findings")
def get_scan_findings(
    scan_id: str,
    severity: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    scan = db.query(ScanJob).filter(ScanJob.scan_id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    assets = db.query(Asset).filter(Asset.scan_id == scan_id).all()
    all_findings = []

    for asset in assets:
        query = db.query(Finding).filter(Finding.asset_id == asset.asset_id)
        if severity:
            query = query.filter(Finding.severity == severity.upper())
        findings = query.all()

        for f in findings:
            compliance_tags = [
                {
                    "framework":   t.framework,
                    "control_ref": t.control_ref,
                    "status":      t.status.value if hasattr(t.status, "value") else t.status,
                }
                for t in (f.compliance_tags or [])
            ]

            remediation_plan = [
                {
                    "steps":           r.steps,
                    "priority":        r.priority,
                    "pqc_alternative": r.pqc_alternative,
                    "status":          r.status,
                }
                for r in (f.remediation_plan or [])
            ]

            all_findings.append({
                "finding_id":      f.finding_id,
                "asset_domain":    asset.domain,
                "asset_id":        asset.asset_id,
                "type":            f.type.value if hasattr(f.type, "value") else f.type,
                "severity":        f.severity,
                "hndl_score":      f.hndl_score,
                "title":           f.title,
                "description":     f.description,
                "remediation":     f.remediation,
                "quantum_risk":    f.quantum_risk,
                "cwe_id":          f.cwe_id,
                "compliance_tags": compliance_tags,
                "remediation_plan": remediation_plan,
            })

    # Sort by severity ranking, then HNDL score
    severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    all_findings.sort(
        key=lambda x: (severity_order.get(x["severity"], 0), x["hndl_score"] or 0),
        reverse=True
    )
    return all_findings


# ── GET /scans/{scan_id}/assets
@router.get("/{scan_id}/assets")
def get_scan_assets(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    assets = db.query(Asset).filter(Asset.scan_id == scan_id).all()

    result = []
    for a in assets:
        certs = db.query(Certificate).filter(Certificate.asset_id == a.asset_id).all()
        ciphers = db.query(CipherSuite).filter(CipherSuite.asset_id == a.asset_id).all()

        result.append({
            "asset_id":        a.asset_id,
            "domain":          a.domain,
            "resolved_ips":    a.resolved_ips or [],
            "hndl_score":      a.hndl_score,
            "is_pqc":          a.is_pqc,
            "pqc_readiness":   a.pqc_readiness.value if a.pqc_readiness else None,
            "protocol":        a.protocol.value if hasattr(a.protocol, "value") else a.protocol,
            "is_cdn":          a.is_cdn,
            "cdn_provider":    a.cdn_provider,
            "is_waf":          a.is_waf,
            "open_ports":      a.open_ports or [],
            "service_category": a.service_category,
            "certificates": [
                {
                    "cert_id":     c.cert_id,
                    "subject":     c.subject,
                    "issuer":      c.issuer,
                    "algorithm":   c.algorithm,
                    "key_size":    c.key_size,
                    "hndl_score":  c.hndl_score,
                    "expires_at":  c.expires_at.isoformat() if c.expires_at else None,
                    "is_pqc":      c.is_pqc,
                }
                for c in certs
            ],
            "cipher_suites": [
                {
                    "suite_id":             cs.suite_id,
                    "name":                 cs.name,
                    "tls_version":          cs.tls_version,
                    "key_exchange":         cs.key_exchange,
                    "quantum_risk":         cs.quantum_risk,
                    "is_quantum_vulnerable": cs.is_quantum_vulnerable,
                    "strength":             cs.strength,
                }
                for cs in ciphers
            ],
        })

    return result


# ── GET /scans/{scan_id}/cbom — CycloneDX CBOM
@router.get("/{scan_id}/cbom")
def get_scan_cbom(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(require_roles(UserRole.ADMIN, UserRole.SECURITY_ANALYST, UserRole.COMPLIANCE_OFFICER))
):
    scan = db.query(ScanJob).filter(ScanJob.scan_id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    cbom = db.query(CBOM).filter(CBOM.scan_id == scan_id).first()
    if not cbom:
        raise HTTPException(status_code=404, detail="CBOM not yet generated for this scan")

    # Return the stored CycloneDX JSON directly — the frontend expects
    # CycloneDX fields: bomFormat, specVersion, cryptoProperties, components, etc.
    return cbom.content


# ── DELETE /scans/{scan_id} — Admin only
@router.delete("/{scan_id}")
def delete_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(require_roles(UserRole.ADMIN))
):
    scan = db.query(ScanJob).filter(ScanJob.scan_id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    db.delete(scan)
    db.commit()
    return {"message": f"Scan {scan_id} deleted"}