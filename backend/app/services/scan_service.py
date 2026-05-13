"""
CloudGuard-AI — Scan Service
Orchestrates the full scan lifecycle:
  1. Create scan record
  2. Run scanners per service
  3. Persist assets to DB
  4. Run rule engine on assets
  5. Persist findings
  6. Compute compliance scores
  7. Trigger AI analysis (async)
"""
from datetime import datetime, timezone

from sqlalchemy import select, func as sql_func
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import refresh_settings
from app.models import Asset, ComplianceResult, Finding, Scan
from app.rules.engine import RuleEngine
from app.scanners import SCANNER_REGISTRY, ScanResult
from app.schemas import ScanCreateRequest, ScanDetail, ScanSummary
from app.services.compliance_service import ComplianceService
from app.utils.constants import (
    SEVERITY_WEIGHTS,
    ScanStatus,
    Severity,
)
from app.utils.exceptions import ScanNotFoundError
from app.utils.logger import get_logger

logger = get_logger(__name__)


class ScanService:

    def __init__(self, db: AsyncSession):
        self._db = db

    # ── Public API ────────────────────────────────────────────────────────

    async def create_scan(self, request: ScanCreateRequest) -> Scan:
        scan = Scan(
            account_id=request.account_id,
            region=request.region,
            services=request.services,
            triggered_by=request.triggered_by,
            status=ScanStatus.PENDING,
        )
        self._db.add(scan)
        await self._db.commit()
        await self._db.refresh(scan)
        logger.info("scan_created", scan_id=scan.id, account=scan.account_id)
        return scan

    async def get_scan(self, scan_id: str) -> Scan:
        result = await self._db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()
        if not scan:
            raise ScanNotFoundError(scan_id)
        return scan

    async def list_scans(self, page: int = 1, limit: int = 20) -> tuple[list[Scan], int]:
        offset = (page - 1) * limit
        result = await self._db.execute(
            select(Scan).order_by(Scan.created_at.desc()).offset(offset).limit(limit)
        )
        scans = result.scalars().all()
        total_result = await self._db.execute(select(sql_func.count(Scan.id)))
        total = total_result.scalar_one()
        return list(scans), total

    async def run_scan(self, scan_id: str) -> None:
        """
        Execute full scan pipeline. Called by Celery worker.
        Updates scan status in real-time.
        """
        scan = await self.get_scan(scan_id)
        await self._update_status(scan, ScanStatus.RUNNING, started_at=datetime.now(timezone.utc))

        try:
            # Step 1: Run all scanners
            # Auto-detect: use mock scanner if no AWS credentials configured
            all_assets: list[ScanResult] = []
            current_settings = refresh_settings()
            use_mock = not bool(current_settings.AWS_ACCESS_KEY_ID)

            if use_mock:
                logger.info("demo_mode_active", reason="no AWS credentials configured, using mock scanner")
                from app.scanners.mock_scanner import MockScanner
                mock = MockScanner(region=scan.region, account_id=scan.account_id)
                all_assets = await mock.scan()
            else:
                for service in scan.services:
                    scanner_cls = SCANNER_REGISTRY.get(service)
                    if not scanner_cls:
                        logger.warning("unknown_service", service=service)
                        continue
                    scanner = scanner_cls(region=scan.region, account_id=scan.account_id)
                    try:
                        assets = await scanner.scan()
                        all_assets.extend(assets)
                        logger.info("service_scan_complete", service=service, assets=len(assets))
                    except Exception as exc:
                        logger.error("scanner_failed", service=service, error=str(exc))

            # Step 2: Persist assets
            asset_map: dict[str, Asset] = {}   # asset_id (ARN) → DB Asset
            for sr in all_assets:
                asset = Asset(
                    scan_id=scan_id,
                    asset_type=sr.asset_type,
                    asset_id=sr.asset_id,
                    asset_name=sr.asset_name,
                    region=sr.region,
                    raw_config=sr.raw_config,
                )
                self._db.add(asset)
                await self._db.flush()  # get generated id
                asset_map[sr.asset_id] = asset

            # Step 3: Run rule engine
            engine = RuleEngine()
            rule_results = engine.evaluate_all(all_assets)

            # Step 4: Persist findings
            severity_counts = {s: 0 for s in Severity}
            for scan_result in all_assets:
                db_asset = asset_map.get(scan_result.asset_id)
                if not db_asset:
                    continue
                rule_findings = rule_results.get(scan_result.asset_id, [])
                for rf in rule_findings:
                    finding = Finding(
                        scan_id=scan_id,
                        asset_id=db_asset.id,
                        rule_id=rf.rule_id,
                        title=rf.title,
                        description=rf.description,
                        severity=rf.severity,
                        compliance_mappings=rf.compliance_mappings,
                    )
                    self._db.add(finding)
                    severity_counts[rf.severity] += 1

            # Step 5: Compute compliance scores
            all_findings_list = [rf for rfs in rule_results.values() for rf in rfs]
            compliance_svc = ComplianceService(self._db)
            await compliance_svc.compute_and_save(scan_id, all_findings_list)

            # Step 6: Update scan summary counts
            total_findings = sum(severity_counts.values())
            await self._db.execute(
                Scan.__table__.update()
                .where(Scan.id == scan_id)
                .values(
                    status=ScanStatus.COMPLETED,
                    completed_at=datetime.now(timezone.utc),
                    total_findings=total_findings,
                    critical_count=severity_counts[Severity.CRITICAL],
                    high_count=severity_counts[Severity.HIGH],
                    medium_count=severity_counts[Severity.MEDIUM],
                    low_count=severity_counts[Severity.LOW],
                )
            )
            await self._db.commit()

            logger.info(
                "scan_completed",
                scan_id=scan_id,
                total_assets=len(all_assets),
                total_findings=total_findings,
            )

        except Exception as exc:
            logger.error("scan_pipeline_failed", scan_id=scan_id, error=str(exc))
            await self._update_status(scan, ScanStatus.FAILED, error_message=str(exc))
            await self._db.commit()
            raise

    # ── Internal ──────────────────────────────────────────────────────────

    async def _update_status(
        self,
        scan: Scan,
        status: ScanStatus,
        started_at: datetime | None = None,
        error_message: str | None = None,
    ) -> None:
        scan.status = status
        if started_at:
            scan.started_at = started_at
        if error_message:
            scan.error_message = error_message
        await self._db.commit()
