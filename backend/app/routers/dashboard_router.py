"""
Dashboard Router - Aggregated metrics and statistics
"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.database import get_db
from app.models.models import ScanJob, Asset, Finding, Certificate, ComplianceTag, ScanStatus, PQCReadiness
from app.auth.auth import get_current_user

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("")
async def get_dashboard(db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    # Total scans
    total_scans = db.query(ScanJob).count()
    completed_scans = db.query(ScanJob).filter(ScanJob.status == ScanStatus.COMPLETED).count()
    running_scans = db.query(ScanJob).filter(ScanJob.status == ScanStatus.RUNNING).count()

    # Assets
    total_assets = db.query(Asset).count()
    quantum_safe = db.query(Asset).filter(Asset.pqc_readiness == PQCReadiness.QUANTUM_SAFE).count()
    vulnerable = db.query(Asset).filter(Asset.pqc_readiness == PQCReadiness.VULNERABLE).count()
    critical = db.query(Asset).filter(Asset.pqc_readiness == PQCReadiness.CRITICAL).count()
    partially_safe = db.query(Asset).filter(Asset.pqc_readiness == PQCReadiness.PARTIALLY_SAFE).count()

    # Average HNDL score
    avg_hndl = db.query(func.avg(Asset.hndl_score)).scalar() or 0.0

    # Findings by severity
    critical_findings = db.query(Finding).filter(Finding.severity == "CRITICAL").count()
    high_findings = db.query(Finding).filter(Finding.severity == "HIGH").count()
    medium_findings = db.query(Finding).filter(Finding.severity == "MEDIUM").count()
    low_findings = db.query(Finding).filter(Finding.severity == "LOW").count()

    # PQC readiness %
    pqc_readiness_pct = round((quantum_safe / total_assets * 100) if total_assets > 0 else 0, 1)

    # Compliance violations by framework
    compliance_counts = {}
    frameworks = ["NIST-PQC", "CERT-IN", "RBI", "NIST-IR-8547"]
    for fw in frameworks:
        count = db.query(ComplianceTag).filter(
            ComplianceTag.framework == fw,
            ComplianceTag.status == "NON_COMPLIANT"
        ).count()
        compliance_counts[fw] = count

    # Recent scans
    recent_scans = db.query(ScanJob).order_by(ScanJob.started_at.desc()).limit(5).all()

    # HNDL distribution
    hndl_distribution = {
        "critical": db.query(Asset).filter(Asset.hndl_score >= 7.5).count(),
        "high": db.query(Asset).filter(Asset.hndl_score >= 5.0, Asset.hndl_score < 7.5).count(),
        "medium": db.query(Asset).filter(Asset.hndl_score >= 2.5, Asset.hndl_score < 5.0).count(),
        "low": db.query(Asset).filter(Asset.hndl_score < 2.5).count(),
    }

    # Protocol distribution
    protocol_data = db.query(Asset.protocol, func.count(Asset.asset_id)).group_by(Asset.protocol).all()

    return {
        "overview": {
            "total_scans": total_scans,
            "completed_scans": completed_scans,
            "running_scans": running_scans,
            "total_assets": total_assets,
            "avg_hndl_score": round(float(avg_hndl), 2),
            "pqc_readiness_percentage": pqc_readiness_pct,
        },
        "pqc_breakdown": {
            "quantum_safe": quantum_safe,
            "partially_safe": partially_safe,
            "vulnerable": vulnerable,
            "critical": critical,
        },
        "findings_summary": {
            "critical": critical_findings,
            "high": high_findings,
            "medium": medium_findings,
            "low": low_findings,
            "total": critical_findings + high_findings + medium_findings + low_findings,
        },
        "compliance": compliance_counts,
        "hndl_distribution": hndl_distribution,
        "protocol_distribution": [{"protocol": str(p), "count": c} for p, c in protocol_data],
        "recent_scans": [
            {
                "scan_id": s.scan_id,
                "org_name": s.org_name,
                "status": s.status.value,
                "started_at": s.started_at.isoformat(),
            }
            for s in recent_scans
        ],
    }
