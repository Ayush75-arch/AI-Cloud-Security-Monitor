"""
CloudGuard-AI — Scan Tasks
Celery task that runs the full scan pipeline asynchronously.
Uses asyncio.run() because Celery workers are synchronous.
"""
import asyncio

from app.workers.celery_app import celery_app
from app.utils.logger import get_logger, setup_logging

logger = get_logger(__name__)

setup_logging()


@celery_app.task(bind=True, name="scan_tasks.run_scan", max_retries=2)
def run_scan_task(self, scan_id: str) -> dict:
    """
    Entry point for async scan execution from Celery.
    Bridges sync Celery ↔ async FastAPI/SQLAlchemy stack.
    """
    logger.info("celery_scan_task_start", scan_id=scan_id, task_id=self.request.id)
    try:
        result = asyncio.run(_run_scan_async(scan_id))
        logger.info("celery_scan_task_complete", scan_id=scan_id)
        return {"scan_id": scan_id, "status": "completed"}
    except Exception as exc:
        logger.error("celery_scan_task_failed", scan_id=scan_id, error=str(exc))
        raise self.retry(exc=exc, countdown=30)


async def _run_scan_async(scan_id: str) -> None:
    """Async scan pipeline — runs inside asyncio.run()."""
    from app.database import AsyncSessionLocal
    from app.services.scan_service import ScanService
    from app.services.ai_service import AIService

    async with AsyncSessionLocal() as db:
        scan_svc = ScanService(db)
        await scan_svc.run_scan(scan_id)

    # AI analysis runs in separate session after scan commits
    async with AsyncSessionLocal() as db:
        ai_svc = AIService(db)
        await ai_svc.analyze_scan_findings(scan_id)
