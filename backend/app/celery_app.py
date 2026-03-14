"""
Celery Tasks - Async scan execution
"""
from celery import Celery
from app.config import settings

celery_app = Celery(
    "qps_scanner",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=["app.tasks.scan_tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_routes={
        "app.tasks.scan_tasks.run_full_scan": {"queue": "scans"},
    },
    beat_schedule={
        "scheduled-rescan-every-day": {
            "task": "app.tasks.scan_tasks.run_scheduled_rescans",
            "schedule": 86400,  # 24 hours
        },
    },
)
