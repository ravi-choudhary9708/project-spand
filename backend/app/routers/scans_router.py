"""
Scans Router - Create and monitor scans
"""
import uuid
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Optional, Any
from app.database import get_db
from app.models.models import ScanJob, Asset, Finding, CBOM, AuditLog, ScanStatus, User
from app.auth.auth import get_current_user, require_analyst
from app.celery_app import celery_app

router = APIRouter(prefix="/api/scans", tags=["scans"])


class ScanRequest(BaseModel):
    org_name: str
    target_assets: List[str]
    authorized: bool = False
    scan_config: dict = {}


class ScanResponse(BaseModel):
    scan_id: str
    org_name: str
    status: str
    progress: int
    current_step: Optional[str] = None
    started_at: datetime
    completed_at: Optional[datetime]
    target_assets: List[str]
    asset_count: int = 0

    class Config:
        from_attributes = True


@router.post("", response_model=ScanResponse)
async def create_scan(
    req: ScanRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    if not req.authorized:
        raise HTTPException(status_code=400, detail="You must confirm authorization to scan these targets.")

    scan = ScanJob(
        scan_id=str(uuid.uuid4()),
        org_name=req.org_name,
        target_assets=req.target_assets,
        authorized=req.authorized,
        scan_config=req.scan_config,
        status=ScanStatus.PENDING,
        created_by=current_user.id,
        progress=0,
    )
    db.add(scan)

    log = AuditLog(
        log_id=str(uuid.uuid4()),
        user_id=current_user.id,
        action="SCAN_CREATED",
        resource_type="scan",
        resource_id=scan.scan_id,
        details={"targets": req.target_assets, "org": req.org_name},
    )
    db.add(log)
    db.commit()

    # Dispatch to Celery
    task = celery_app.send_task("app.tasks.scan_tasks.run_full_scan", args=[scan.scan_id], queue="scans")
    scan.celery_task_id = task.id
    db.commit()

    return ScanResponse(
        scan_id=scan.scan_id,
        org_name=scan.org_name,
        status=scan.status.value,
        progress=scan.progress,
        current_step="Pending Task Dispatch",
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        target_assets=scan.target_assets or [],
    )


@router.get("", response_model=List[ScanResponse])
async def list_scans(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scans = db.query(ScanJob).order_by(ScanJob.started_at.desc()).limit(50).all()
    result = []
    for scan in scans:
        asset_count = db.query(Asset).filter(Asset.scan_id == scan.scan_id).count()
        
        current_step = None
        if scan.status == ScanStatus.RUNNING and scan.celery_task_id:
            try:
                task = celery_app.AsyncResult(scan.celery_task_id)
                if task.state == "PROGRESS" and task.info:
                    current_step = task.info.get("step")
            except Exception:
                pass

        result.append(ScanResponse(
            scan_id=scan.scan_id,
            org_name=scan.org_name,
            status=scan.status.value,
            progress=scan.progress,
            current_step=current_step,
            started_at=scan.started_at,
            completed_at=scan.completed_at,
            target_assets=scan.target_assets or [],
            asset_count=asset_count,
        ))
    return result


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scan = db.query(ScanJob).filter(ScanJob.scan_id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    current_step = None
    # Also check Celery task status if still running
    if scan.status == ScanStatus.RUNNING and scan.celery_task_id:
        try:
            task = celery_app.AsyncResult(scan.celery_task_id)
            if task.state == "PROGRESS" and task.info:
                scan.progress = task.info.get("progress", scan.progress)
                current_step = task.info.get("step")
        except Exception:
            pass

    asset_count = db.query(Asset).filter(Asset.scan_id == scan_id).count()
    return ScanResponse(
        scan_id=scan.scan_id,
        org_name=scan.org_name,
        status=scan.status.value,
        progress=scan.progress,
        current_step=current_step,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        target_assets=scan.target_assets or [],
        asset_count=asset_count,
    )


@router.get("/{scan_id}/assets")
async def get_scan_assets(scan_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    assets = db.query(Asset).filter(Asset.scan_id == scan_id).all()
    return [_serialize_asset(a) for a in assets]


@router.get("/{scan_id}/findings")
async def get_scan_findings(scan_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    assets = db.query(Asset).filter(Asset.scan_id == scan_id).all()
    all_findings = []
    for asset in assets:
        for f in asset.findings:
            all_findings.append({
                "finding_id": f.finding_id,
                "asset_domain": asset.domain,
                "type": f.type.value,
                "severity": f.severity,
                "hndl_score": f.hndl_score,
                "title": f.title,
                "description": f.description,
                "remediation": f.remediation,
                "quantum_risk": f.quantum_risk,
                "cwe_id": f.cwe_id,
            })
    return all_findings


@router.get("/{scan_id}/cbom")
async def get_scan_cbom(scan_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    cbom = db.query(CBOM).filter(CBOM.scan_id == scan_id).first()
    if not cbom:
        raise HTTPException(status_code=404, detail="CBOM not yet generated for this scan")
    return cbom.content


@router.delete("/{scan_id}")
async def cancel_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    scan = db.query(ScanJob).filter(ScanJob.scan_id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.celery_task_id:
        celery_app.control.revoke(scan.celery_task_id, terminate=True)
    scan.status = ScanStatus.CANCELLED
    db.commit()
    return {"message": "Scan cancelled"}


def _serialize_asset(a: Asset) -> dict:
    return {
        "asset_id": a.asset_id,
        "domain": a.domain,
        "resolved_ips": a.resolved_ips,
        "protocol": a.protocol.value if a.protocol else None,
        "is_cdn": a.is_cdn,
        "hndl_score": a.hndl_score,
        "is_pqc": a.is_pqc,
        "pqc_readiness": a.pqc_readiness.value if a.pqc_readiness else None,
        "open_ports": a.open_ports,
        "service_category": a.service_category,
        "findings_count": len(a.findings),
        "certificates_count": len(a.certificates),
    }
