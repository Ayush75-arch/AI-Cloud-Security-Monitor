"""
CloudGuard-AI — Security Trend Service
Tracks security posture over time by storing scan snapshots.
Enables trend graphs: compliance score over time, finding count over time.
"""
from datetime import datetime, timezone

from sqlalchemy import select, func as sql_func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import ComplianceResult, Finding, Scan
from app.utils.constants import FindingStatus, Severity
from app.utils.logger import get_logger

logger = get_logger(__name__)


class TrendService:

    def __init__(self, db: AsyncSession):
        self._db = db

    async def get_compliance_trend(self, framework: str | None = None, limit: int = 20) -> list[dict]:
        query = (
            select(ComplianceResult)
            .order_by(ComplianceResult.computed_at.desc())
            .limit(limit)
        )
        if framework:
            query = query.where(ComplianceResult.framework == framework)

        result = await self._db.execute(query)
        rows = result.scalars().all()

        trend: list[dict] = []
        for row in reversed(rows):
            trend.append({
                "id": row.id,
                "scan_id": row.scan_id,
                "framework": row.framework,
                "score": row.score,
                "passed": row.passed_controls,
                "failed": row.failed_controls,
                "computed_at": row.computed_at.isoformat() if row.computed_at else None,
            })

        return trend

    async def get_finding_trend(self, limit: int = 20) -> list[dict]:
        query = (
            select(Scan)
            .where(Scan.status == "completed")
            .order_by(Scan.created_at.desc())
            .limit(limit)
        )
        result = await self._db.execute(query)
        scans = result.scalars().all()

        trend: list[dict] = []
        for scan in reversed(scans):
            trend.append({
                "scan_id": scan.id,
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                "created_at": scan.created_at.isoformat() if scan.created_at else None,
                "total": scan.total_findings,
                "critical": scan.critical_count,
                "high": scan.high_count,
                "medium": scan.medium_count,
                "low": scan.low_count,
            })

        return trend

    async def get_security_score_trend(self, limit: int = 20) -> list[dict]:
        query = (
            select(Scan)
            .where(Scan.status == "completed")
            .order_by(Scan.created_at.desc())
            .limit(limit)
        )
        result = await self._db.execute(query)
        scans = result.scalars().all()

        trend: list[dict] = []
        for scan in reversed(scans):
            total = scan.total_findings or 1
            risk_raw = (
                scan.critical_count * 10 +
                scan.high_count * 7 +
                scan.medium_count * 4 +
                scan.low_count * 1
            )
            risk_score = min(round((risk_raw / total) * 10, 1), 100.0)
            security_score = max(0, round(100.0 - risk_score, 1))

            trend.append({
                "scan_id": scan.id,
                "timestamp": scan.completed_at.isoformat() if scan.completed_at else scan.created_at.isoformat(),
                "security_score": security_score,
                "risk_score": risk_score,
                "total_findings": scan.total_findings,
            })

        return trend
