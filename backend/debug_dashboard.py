from sqlalchemy import create_engine, func
from sqlalchemy.orm import sessionmaker
import sys
import os

# Add the backend directory to sys.path
sys.path.append(os.path.join(os.getcwd(), "backend"))

from app.database import Base, engine, SessionLocal
from app.models.models import ScanJob, Asset, Finding, Certificate, ComplianceTag, ScanStatus, PQCReadiness

def test_dashboard_logic():
    db = SessionLocal()
    try:
        print("Starting dashboard logic test...")
        
        # Total scans
        total_scans = db.query(ScanJob).count()
        print(f"Total scans: {total_scans}")
        
        completed_scans = db.query(ScanJob).filter(ScanJob.status == ScanStatus.COMPLETED).count()
        running_scans = db.query(ScanJob).filter(ScanJob.status == ScanStatus.RUNNING).count()

        # Assets
        total_assets = db.query(Asset).count()
        print(f"Total assets: {total_assets}")
        
        quantum_safe = db.query(Asset).filter(Asset.pqc_readiness == PQCReadiness.QUANTUM_SAFE).count()
        vulnerable = db.query(Asset).filter(Asset.pqc_readiness == PQCReadiness.VULNERABLE).count()
        critical = db.query(Asset).filter(Asset.pqc_readiness == PQCReadiness.CRITICAL).count()
        partially_safe = db.query(Asset).filter(Asset.pqc_readiness == PQCReadiness.PARTIALLY_SAFE).count()

        # Average HNDL score
        avg_hndl = db.query(func.avg(Asset.hndl_score)).scalar() or 0.0
        print(f"Average HNDL: {avg_hndl}")

        # Findings
        critical_findings = db.query(Finding).filter(Finding.severity == "CRITICAL").count()
        total_findings = db.query(Finding).count()
        print(f"Total findings: {total_findings}")

        # PQC readiness %
        pqc_ready_pct = round((quantum_safe / total_assets * 100) if total_assets > 0 else 0, 1)

        # Risk distribution
        critical_pct = round((critical / total_assets * 100) if total_assets > 0 else 0, 1)
        vulnerable_pct = round((vulnerable / total_assets * 100) if total_assets > 0 else 0, 1)
        partial_pct = round((partially_safe / total_assets * 100) if total_assets > 0 else 0, 1)

        # Compliance
        compliance = {}
        frameworks = ["NIST-PQC", "CERT-IN", "RBI", "NIST-IR-8547"]
        for fw in frameworks:
            count = db.query(ComplianceTag).filter(
                ComplianceTag.framework == fw,
                ComplianceTag.status == "NON_COMPLIANT"
            ).count()
            compliance[fw] = count
        print(f"Compliance status: {compliance}")

        # Recent scans
        print("Fetching recent scans...")
        recent_scans_q = db.query(ScanJob).order_by(ScanJob.started_at.desc()).limit(5).all()
        recent_scans = []
        for s in recent_scans_q:
            asset_count = db.query(Asset).filter(Asset.scan_id == s.scan_id).count()
            scan_avg_hndl = db.query(func.avg(Asset.hndl_score)).filter(Asset.scan_id == s.scan_id).scalar()
            scan_quantum_safe = db.query(Asset).filter(
                Asset.scan_id == s.scan_id,
                Asset.pqc_readiness == PQCReadiness.QUANTUM_SAFE
            ).count()
            
            # Potential crash point: division by zero or None handle
            scan_pqc_pct = round((scan_quantum_safe / asset_count * 100) if asset_count > 0 else 0, 1)
            
            print(f"Scan {s.scan_id}: assets={asset_count}, avg_hndl={scan_avg_hndl}")
            
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

        # Last scan
        last_scan_job = db.query(ScanJob).order_by(ScanJob.started_at.desc()).first()
        last_scan = last_scan_job.started_at.isoformat() if last_scan_job and last_scan_job.started_at else None

        # Algorithm breakdown
        print("Algorithm breakdown...")
        algo_data = db.query(
            Certificate.algorithm, func.count(Certificate.cert_id)
        ).group_by(Certificate.algorithm).all()
        print(f"Algo data: {algo_data}")

        # Key size breakdown
        print("Key size breakdown...")
        key_size_data = db.query(
            Certificate.key_size, func.count(Certificate.cert_id)
        ).filter(Certificate.key_size != None).group_by(Certificate.key_size).order_by(Certificate.key_size).all()
        print(f"Key size counts: {key_size_data}")

        # Distribution queries
        print("Distribution queries...")
        protocol_data = db.query(Asset.protocol, func.count(Asset.asset_id)).group_by(Asset.protocol).all()
        server_data = db.query(Asset.server_software, func.count(Asset.asset_id)).filter(Asset.server_software != None).group_by(Asset.server_software).all()
        cdn_data = db.query(Asset.cdn_provider, func.count(Asset.asset_id)).filter(Asset.cdn_provider != None).group_by(Asset.cdn_provider).all()
        service_data = db.query(Asset.service_category, func.count(Asset.asset_id)).group_by(Asset.service_category).all()
        network_data = db.query(Asset.network_type, func.count(Asset.asset_id)).group_by(Asset.network_type).all()

        print("Test COMPLETED successfully!")

    except Exception as e:
        print(f"Test FAILED with error: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
    finally:
        db.close()

if __name__ == "__main__":
    test_dashboard_logic()
