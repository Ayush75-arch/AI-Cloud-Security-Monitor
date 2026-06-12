"""
CloudGuard-AI — Celery Worker (NOT CURRENTLY WIRED)

Scans run via FastAPI BackgroundTasks. This module is retained if you want
distributed task execution. To enable: set CELERY_BROKER_URL in .env,
run a celery worker, and replace BackgroundTasks in router.py with
scan_tasks.run_scan_task.delay().
"""
from celery import Celery

from app.config import settings

celery_app = Celery(
    "cloudguard",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=["app.workers.scan_tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,   # One task at a time per worker
    task_soft_time_limit=600,       # 10 min soft limit
    task_time_limit=900,            # 15 min hard limit
)
