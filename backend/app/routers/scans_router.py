"""
Scans Router — QuantumShield API
Place at: backend/app/routers/scans_router.py
"""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List, Optional
import uuid
import datetime

from ..database import get_db
from ..models.models import (
    ScanJob, ScanStatus, Asset, Finding, ComplianceTag,
    RemediationPlaybook, Certificate, CipherSuite, CBOM
)
from ..auth.auth import get_current_user, require_roles
from ..tasks.scan_tasks import run_full_scan
from ..celery_app import celery_app

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("")
def start_scan(
    body: dict,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user=Depends(require_roles(["ADMIN", "SECURITY_ANALYST", "SOC_TEAM"]))
):
    target_domain = body.get("target_domain", "").strip()
    if not target_domain:
        raise HTTPException(status_code=400, detail="target_domain is required")

    scan_id = str(uuid.uuid4())
    scan = ScanJob(
        scan_id=scan_id,
        target_domain=target_domain,
        org_name=body.get("org_name", target_domain),
        status=ScanStatus.PENDING,
        initiated_by=current_user.username,
        created_at=datetime.datetime.utcnow(),
    )
    db.add(scan)
    db.commit()

    # Dispatch to Celery
    celery_app.send_task("tasks.scan_tasks.run_full_scan", args=[scan_id])

    return {"scan_id": scan_id, "status": "PENDING", "message": "Scan queued successfully"}



@router.get("")
def list_scans(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    scans = db.query(ScanJob).order_by(ScanJob.created_at.desc()).limit(50).all()
    return [
        {
            "scan_id":       s.scan_id,
            "target_domain": s.target_domain,
            "org_name":      s.org_name,
            "status":        s.status.value,
            "total_assets":  s.total_assets,
            "avg_hndl":      s.avg_hndl_score,
            "pqc_ready_pct": s.pqc_ready_percentage,
            "created_at":    s.created_at.isoformat() if s.created_at else None,
            "completed_at":  s.completed_at.isoformat() if s.completed_at else None,
            "initiated_by":  s.initiated_by,
        }
        for s in scans
    ]


@router.get("/{scan_id}")
def get_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    scan = db.query(ScanJob).filter(ScanJob.scan_id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return {
        "scan_id":           scan.scan_id,
        "target_domain":     scan.target_domain,
        "org_name":          scan.org_name,
        "status":            scan.status.value,
        "progress_stage":    scan.progress_stage,
        "progress_pct":      scan.progress_pct,
        "total_assets":      scan.total_assets,
        "avg_hndl":          scan.avg_hndl_score,
        "pqc_ready_pct":     scan.pqc_ready_percentage,
        "critical_findings": scan.critical_findings_count,
        "created_at":        scan.created_at.isoformat() if scan.created_at else None,
        "completed_at":      scan.completed_at.isoformat() if scan.completed_at else None,
        "initiated_by":      scan.initiated_by,
        "error_message":     scan.error_message,
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
            query = query.filter(Finding.severity == int(severity))
        findings = query.all()

        for f in findings:
            # ── Compliance tags ──────────────────────────────────────────
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
                    "title":           r.title,
                    "steps":           r.steps,
                    "priority":        r.priority,
                    "pqc_alternative": r.pqc_alternative,
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

    all_findings.sort(key=lambda x: (x["severity"] or 0, x["hndl_score"] or 0), reverse=True)
    return all_findings


# ── GET /scans/{scan_id}/assets —
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
            "ip_address":      a.ip_address,
            "asset_type":      a.asset_type.value if hasattr(a.asset_type, "value") else a.asset_type,
            "hndl_score":      a.hndl_score,
            "pqc_ready":       a.pqc_ready,
            "tls_version":     a.tls_version,
            "protocol":        a.protocol.value if hasattr(a.protocol, "value") else a.protocol,
            "is_cdn":          a.is_cdn,
            "cdn_provider":    a.cdn_provider,
            "certificates": [
                {
                    "subject":       c.subject,
                    "issuer":        c.issuer,
                    "algorithm":     c.algorithm,
                    "key_size":      c.key_size,
                    "valid_from":    c.valid_from.isoformat() if c.valid_from else None,
                    "valid_until":   c.valid_until.isoformat() if c.valid_until else None,
                    "is_expired":    c.is_expired,
                    "days_to_expiry": c.days_to_expiry,
                }
                for c in certs
            ],
            "cipher_suites": [
                {
                    "name":         cs.name,
                    "tls_version":  cs.tls_version,
                    "key_exchange": cs.key_exchange,
                    "is_quantum_safe": cs.is_quantum_safe,
                }
                for cs in ciphers
            ],
        })

    return result


# ── GET /scans/{scan_id}/cbom — CycloneDX 1.4 CBOM 
@router.get("/{scan_id}/cbom")
def get_scan_cbom(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(require_roles(["ADMIN", "SECURITY_ANALYST", "COMPLIANCE_OFFICER"]))
):
    scan = db.query(ScanJob).filter(ScanJob.scan_id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    cbom = db.query(CBOM).filter(CBOM.scan_id == scan_id).first()
    if not cbom:
        raise HTTPException(status_code=404, detail="CBOM not yet generated for this scan")

    return {
        "cbom_id":        cbom.cbom_id,
        "scan_id":        cbom.scan_id,
        "format":         cbom.format,
        "spec_version":   cbom.spec_version,
        "component_count": cbom.component_count,
        "generated_at":   cbom.generated_at.isoformat() if cbom.generated_at else None,
        "cbom_json":      cbom.cbom_json,
    }


# ── DELETE /scans/{scan_id} — Admin only ─────────────────────────────────────
@router.delete("/{scan_id}")
def delete_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(require_roles(["ADMIN"]))
):
    scan = db.query(ScanJob).filter(ScanJob.scan_id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    db.delete(scan)
    db.commit()
    return {"message": f"Scan {scan_id} deleted"}