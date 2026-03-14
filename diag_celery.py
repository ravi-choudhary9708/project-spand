from app.celery_app import celery_app
from celery.result import AsyncResult
from app.database import SessionLocal
from app.models.models import ScanJob

db = SessionLocal()
scans = db.query(ScanJob).filter(ScanJob.status == 'RUNNING').all()

for s in scans:
    res = AsyncResult(s.celery_task_id, app=celery_app)
    print(f"ScanID: {s.scan_id}")
    print(f"TaskID: {s.celery_task_id}")
    print(f"State: {res.state}")
    print(f"Info: {res.info}")
    print("-" * 20)
db.close()
