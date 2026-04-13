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


@router.get("", summary="Get Dashboard Dashboard metrics", description="Returns aggregated statistics on scans, assets, compliance and PQC readiness across the platform.")
@router.get("/stats", summary="Get Global Dashboard Stats", description="Alias for the main dashboard metrics. Both return the exact same flat dict.")
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
    total_findings = critical_findings + high_findings + medium_findings + low_findings

    # PQC readiness %
    pqc_ready_pct = round((quantum_safe / total_assets * 100) if total_assets > 0 else 0, 1)

    # Risk distribution percentages for pie chart
    critical_pct = round((critical / total_assets * 100) if total_assets > 0 else 0, 1)
    vulnerable_pct = round((vulnerable / total_assets * 100) if total_assets > 0 else 0, 1)
    partial_pct = round((partially_safe / total_assets * 100) if total_assets > 0 else 0, 1)

    # Compliance violations by framework
    compliance = {}
    frameworks = ["NIST-PQC", "CERT-IN", "RBI", "NIST-IR-8547"]
    for fw in frameworks:
        count = db.query(ComplianceTag).filter(
            ComplianceTag.framework == fw,
            ComplianceTag.status == "NON_COMPLIANT"
        ).count()
        compliance[fw] = count

    # Recent scans
    recent_scans_q = db.query(ScanJob).order_by(ScanJob.started_at.desc()).limit(5).all()
    recent_scans = []
    for s in recent_scans_q:
        asset_count = db.query(Asset).filter(Asset.scan_id == s.scan_id).count()
        scan_avg_hndl = db.query(func.avg(Asset.hndl_score)).filter(Asset.scan_id == s.scan_id).scalar()
        scan_quantum_safe = db.query(Asset).filter(
            Asset.scan_id == s.scan_id,
            Asset.pqc_readiness == PQCReadiness.QUANTUM_SAFE
        ).count()
        scan_pqc_pct = round((scan_quantum_safe / asset_count * 100) if asset_count > 0 else 0, 1)
        recent_scans.append({
            "scan_id": s.scan_id,
            "org_name": s.org_name,
            "target_domain": (s.target_assets[0] if s.target_assets else s.org_name),
            "status": s.status.value if s.status else "PENDING",
            "total_assets": asset_count,
            "avg_hndl": round(float(scan_avg_hndl), 2) if scan_avg_hndl else 0.0,
            "pqc_ready_pct": scan_pqc_pct,
            "started_at": s.started_at.isoformat() if s.started_at else None,
            "initiated_by": None,
        })

    # Last scan date
    last_scan_job = db.query(ScanJob).order_by(ScanJob.started_at.desc()).first()
    last_scan = last_scan_job.started_at.isoformat() if last_scan_job and last_scan_job.started_at else None

    # Algorithm breakdown — real data from scanner (certificate algorithms)
    # Include quantum_vulnerable flag so frontend can color-code bars
    QUANTUM_VULN_ALGOS = {"RSA", "ECDSA", "ECDH", "ECDHE", "DHE", "DH", "DSA", "ECC"}
    PQC_SAFE_ALGOS    = {"CRYSTALS-KYBER", "CRYSTALS-DILITHIUM", "FALCON", "SPHINCS+",
                         "ED25519", "ED448", "KYBER", "DILITHIUM"}

    algo_data = db.query(
        Certificate.algorithm, func.count(Certificate.cert_id)
    ).group_by(Certificate.algorithm).all()
    algo_breakdown = []
    for algo, count in algo_data:
        algo_upper = (algo or "").upper()
        if any(a in algo_upper for a in QUANTUM_VULN_ALGOS):
            quantum_vuln = True
        elif any(a in algo_upper for a in PQC_SAFE_ALGOS):
            quantum_vuln = False
        else:
            quantum_vuln = None   # unknown
        algo_breakdown.append({
            "algorithm": algo or "Unknown",
            "count": count,
            "quantum_vulnerable": quantum_vuln,
        })

    # Key size breakdown — real data from scanner
    key_size_data = db.query(
        Certificate.key_size, func.count(Certificate.cert_id)
    ).filter(Certificate.key_size != None).group_by(Certificate.key_size).order_by(Certificate.key_size).all()
    key_size_breakdown = [
        {"key_size": ks, "count": cnt}
        for ks, cnt in key_size_data
        if ks is not None
    ]

    # HNDL distribution
    hndl_distribution = {
        "critical": db.query(Asset).filter(Asset.hndl_score >= 7.5).count(),
        "high": db.query(Asset).filter(Asset.hndl_score >= 5.0, Asset.hndl_score < 7.5).count(),
        "medium": db.query(Asset).filter(Asset.hndl_score >= 2.5, Asset.hndl_score < 5.0).count(),
        "low": db.query(Asset).filter(Asset.hndl_score < 2.5).count(),
    }

    # Protocol distribution
    protocol_data = db.query(Asset.protocol, func.count(Asset.asset_id)).group_by(Asset.protocol).all()

    # Server software distribution
    server_data = db.query(Asset.server_software, func.count(Asset.asset_id)).filter(Asset.server_software != None).group_by(Asset.server_software).all()
    
    # CDN provider distribution
    cdn_data = db.query(Asset.cdn_provider, func.count(Asset.asset_id)).filter(Asset.cdn_provider != None).group_by(Asset.cdn_provider).all()

    # Service category distribution (refined)
    service_data = db.query(Asset.service_category, func.count(Asset.asset_id)).group_by(Asset.service_category).all()

    # Network type distribution
    network_data = db.query(Asset.network_type, func.count(Asset.asset_id)).group_by(Asset.network_type).all()

    return {
        # ── Flat fields for frontend KPI cards ──
        "total_scans": total_scans,
        "completed_scans": completed_scans,
        "running_scans": running_scans,
        "total_assets": total_assets,
        "avg_hndl": round(float(avg_hndl), 2),
        "pqc_ready_pct": pqc_ready_pct,
        "critical_findings": critical_findings,
        "high_findings": high_findings,
        "medium_findings": medium_findings,
        "low_findings": low_findings,
        "total_findings": total_findings,
        "last_scan": last_scan,

        # ── Risk distribution percentages for pie chart ──
        "critical_pct": critical_pct,
        "vulnerable_pct": vulnerable_pct,
        "partial_pct": partial_pct,

        # ── Breakdowns ──
        "pqc_breakdown": {
            "quantum_safe": quantum_safe,
            "partially_safe": partially_safe,
            "vulnerable": vulnerable,
            "critical": critical,
        },
        "compliance": compliance,
        "hndl_distribution": hndl_distribution,
        "algo_breakdown": algo_breakdown,
        "key_size_breakdown": key_size_breakdown,
        "protocol_distribution": [{"protocol": str(p), "count": c} for p, c in protocol_data],
        "server_distribution": [{"server": s, "count": c} for s, c in server_data],
        "cdn_distribution": [{"provider": p, "count": c} for p, c in cdn_data],
        "service_distribution": [{"category": s, "count": c} for s, c in service_data],
        "recent_scans": recent_scans,
    }
