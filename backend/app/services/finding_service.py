"""
CloudGuard-AI — Finding Service
CRUD operations and filtering for security findings.
"""
from sqlalchemy import select, func as sql_func, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models import Finding
from app.utils.constants import FindingStatus
from app.utils.exceptions import FindingNotFoundError
from app.utils.logger import get_logger

logger = get_logger(__name__)


class FindingService:

    def __init__(self, db: AsyncSession):
        self._db = db

    async def get_finding(self, finding_id: str) -> Finding:
        result = await self._db.execute(
            select(Finding)
            .options(selectinload(Finding.asset))
            .where(Finding.id == finding_id)
        )
        finding = result.scalar_one_or_none()
        if not finding:
            raise FindingNotFoundError(finding_id)
        return finding

    async def list_findings(
        self,
        scan_id: str | None = None,
        severity: str | None = None,
        status: str | None = None,
        rule_id: str | None = None,
        page: int = 1,
        limit: int = 50,
    ) -> tuple[list[Finding], int]:
        query = select(Finding).options(selectinload(Finding.asset))

        if scan_id:
            query = query.where(Finding.scan_id == scan_id)
        if severity:
            query = query.where(Finding.severity == severity)
        if status:
            query = query.where(Finding.status == status)
        if rule_id:
            query = query.where(Finding.rule_id == rule_id)

        count_q = select(sql_func.count()).select_from(query.subquery())
        total_result = await self._db.execute(count_q)
        total = total_result.scalar_one()

        offset = (page - 1) * limit
        query = query.order_by(Finding.created_at.desc()).offset(offset).limit(limit)
        result = await self._db.execute(query)
        findings = result.scalars().all()

        return list(findings), total

    async def suppress_finding(self, finding_id: str, reason: str) -> Finding:
        finding = await self.get_finding(finding_id)
        finding.status = FindingStatus.SUPPRESSED
        finding.suppressed_reason = reason
        await self._db.commit()
        await self._db.refresh(finding)
        logger.info("finding_suppressed", finding_id=finding_id)
        return finding

    async def resolve_finding(self, finding_id: str) -> Finding:
        finding = await self.get_finding(finding_id)
        finding.status = FindingStatus.RESOLVED
        await self._db.commit()
        await self._db.refresh(finding)
        return finding
