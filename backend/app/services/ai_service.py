"""
CloudGuard-AI — AI Service
Factory for AI adapter selection. Batch-analyzes findings post-scan.
Persists AI results to DB.
"""
import asyncio

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.base_adapter import BaseAIAdapter
from app.config import refresh_settings
from app.models import Finding
from app.utils.exceptions import AIProviderError
from app.utils.logger import get_logger

logger = get_logger(__name__)


def get_ai_adapter() -> BaseAIAdapter:
    """Factory: returns configured AI adapter based on AI_PROVIDER setting."""
    current_settings = refresh_settings()
    if current_settings.AI_PROVIDER == "groq":
        from app.ai.groq_adapter import GROQAdapter
        return GROQAdapter()
    elif current_settings.AI_PROVIDER == "local":
        from app.ai.local_llm_adapter import LocalLLMAdapter
        return LocalLLMAdapter()
    else:
        raise AIProviderError(f"Unknown AI_PROVIDER: {current_settings.AI_PROVIDER}")


class AIService:
    """
    Coordinates AI analysis for scan findings.
    Runs concurrently with rate limiting to avoid API throttling.
    """

    def __init__(self, db: AsyncSession):
        self._db = db
        self._adapter = get_ai_adapter()

    async def analyze_scan_findings(self, scan_id: str) -> int:
        """
        Fetch all open findings for a scan, analyze with AI, persist results.
        Returns number of findings analyzed.
        """
        result = await self._db.execute(
            select(Finding).where(
                Finding.scan_id == scan_id,
                Finding.ai_explanation.is_(None),
            )
        )
        findings = result.scalars().all()

        if not findings:
            logger.info("ai_no_findings_to_analyze", scan_id=scan_id)
            return 0

        logger.info("ai_analysis_start", scan_id=scan_id, count=len(findings))

        # Concurrency limit — don't hammer the API
        semaphore = asyncio.Semaphore(3)
        tasks = [self._analyze_finding(finding, semaphore) for finding in findings]
        await asyncio.gather(*tasks, return_exceptions=True)

        logger.info("ai_analysis_complete", scan_id=scan_id, analyzed=len(findings))
        return len(findings)

    async def _analyze_finding(self, finding: Finding, semaphore: asyncio.Semaphore) -> None:
        async with semaphore:
            try:
                # Lazy-load asset for name/type
                await self._db.refresh(finding, ["asset"])
                asset_type = finding.asset.asset_type if finding.asset else "unknown"
                asset_name = finding.asset.asset_name if finding.asset else "unknown"

                analysis = await self._adapter.analyze_finding(
                    rule_id=finding.rule_id,
                    title=finding.title,
                    description=finding.description,
                    severity=finding.severity,
                    asset_type=asset_type,
                    asset_name=asset_name,
                )

                await self._db.execute(
                    update(Finding)
                    .where(Finding.id == finding.id)
                    .values(
                        ai_explanation=analysis.explanation,
                        ai_attack_scenario=analysis.attack_scenario,
                        ai_remediation=analysis.remediation,
                    )
                )
                await self._db.commit()

            except AIProviderError as exc:
                logger.warning("ai_analysis_failed", finding_id=finding.id, error=str(exc))
            except Exception as exc:
                logger.error("ai_analysis_unexpected_error", finding_id=finding.id, error=str(exc))
