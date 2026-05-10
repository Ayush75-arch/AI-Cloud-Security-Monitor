"""
CloudGuard-AI — Celery Worker
Async task queue for long-running scan jobs.
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
