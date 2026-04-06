import sys
import os
import uuid
from sqlalchemy.orm import Session
from app.database import SessionLocal, engine
from app.models.models import ScanJob, ScanStatus, Asset
from app.tasks.scan_tasks import run_full_scan

def verify():
    db: Session = SessionLocal()
    scan_id = str(uuid.uuid4())
    
    # Create a dummy scan job
    scan = ScanJob(
        scan_id=scan_id,
        org_name="Verification Org",
        target_assets=["google.com"],
        status=ScanStatus.PENDING
    )
    db.add(scan)
    db.commit()
    
    print(f"Starting scan for {scan_id}...")
    # Run the scan synchronously for verification
    run_full_scan(scan_id, full_scan=False)
    
    # Check results
    assets = db.query(Asset).filter(Asset.scan_id == scan_id).all()
    print(f"Scan complete. Found {len(assets)} assets.")
    for a in assets:
        print(f"Asset: {a.domain}")
        print(f"  Category: {a.service_category}")
        print(f"  Server: {a.server_software}")
        print(f"  CDN: {a.cdn_provider}")
        print(f"  Is CDN: {a.is_cdn}")

if __name__ == "__main__":
    verify()
