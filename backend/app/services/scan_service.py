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
from app.models import Asset, Finding, Scan
from app.rules.engine import RuleEngine
from app.scanners import SCANNER_REGISTRY, ScanResult
from app.schemas import ScanCreateRequest
from app.services.compliance_service import ComplianceService
from app.utils.constants import (
    FindingStatus,
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

            if "azure" in (scan.services or []):
                logger.info("azure_scan_active")
                from app.scanners.azure_scanner import AzureScanner
                try:
                    azure = AzureScanner(region=scan.region, account_id=scan.account_id)
                    azure_assets = await azure.scan()
                    all_assets.extend(azure_assets)
                except Exception as exc:
                    logger.error("azure_scan_failed", error=str(exc))

            if "gcp" in (scan.services or []):
                logger.info("gcp_scan_active")
                from app.scanners.gcp_scanner import GCPScanner
                try:
                    gcp = GCPScanner(region=scan.region, account_id=scan.account_id)
                    gcp_assets = await gcp.scan()
                    all_assets.extend(gcp_assets)
                except Exception as exc:
                    logger.error("gcp_scan_failed", error=str(exc))

            if use_mock:
                logger.info("demo_mode_active", reason="no AWS credentials configured, using mock scanner")
                from app.scanners.mock_scanner import MockScanner
                mock = MockScanner(region=scan.region, account_id=scan.account_id)
                mock_assets = await mock.scan()
                all_assets.extend(mock_assets)
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

            # Step 4: Persist findings (with deduplication by fingerprint)
            import hashlib
            severity_counts = {s: 0 for s in Severity}
            current_fingerprints: set[str] = set()

            for scan_result in all_assets:
                db_asset = asset_map.get(scan_result.asset_id)
                if not db_asset:
                    continue
                rule_findings = rule_results.get(scan_result.asset_id, [])
                for rf in rule_findings:
                    # Fingerprint = hash(rule_id + asset ARN) — stable across scans
                    fingerprint = hashlib.sha256(
                        f"{rf.rule_id}:{scan_result.asset_id}".encode()
                    ).hexdigest()[:16]
                    current_fingerprints.add(fingerprint)
                    finding = Finding(
                        scan_id=scan_id,
                        asset_id=db_asset.id,
                        rule_id=rf.rule_id,
                        title=rf.title,
                        description=rf.description,
                        severity=rf.severity,
                        compliance_mappings=rf.compliance_mappings,
                        fingerprint=fingerprint,
                    )
                    self._db.add(finding)
                    severity_counts[rf.severity] += 1

            # Auto-resolve findings whose fingerprint no longer appears in this scan
            # (i.e. the misconfiguration was fixed between scans)
            if current_fingerprints:
                prev_open = await self._db.execute(
                    select(Finding).where(
                        Finding.status == FindingStatus.OPEN,
                        Finding.fingerprint.isnot(None),
                        Finding.scan_id != scan_id,
                    )
                )
                for prev in prev_open.scalars().all():
                    if prev.fingerprint not in current_fingerprints:
                        prev.status = FindingStatus.RESOLVED
                        prev.resolved_at = datetime.now(timezone.utc)
                        logger.info(
                            "finding_auto_resolved",
                            fingerprint=prev.fingerprint,
                            rule_id=prev.rule_id,
                        )

            # Step 5: Compute compliance scores
            all_findings_list = [rf for rfs in rule_results.values() for rf in rfs]
            compliance_svc = ComplianceService(self._db)
            await compliance_svc.compute_and_save(scan_id, all_findings_list)

            # Step 6: Update scan summary counts
            total_findings = sum(severity_counts.values())
            await self._db.execute(
                Scan.__table__.update().where(Scan.id == scan_id)  # type: ignore[attr-defined]
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

    async def run_scan_with_ai(self, scan_id: str) -> None:
        """
        Full scan pipeline + async AI analysis.
        Use this from BackgroundTasks — keeps all orchestration in the service layer.
        Uses a separate DB session for AI so the scan session is fully closed first.
        """
        await self.run_scan(scan_id)

        current_settings = refresh_settings()
        if not current_settings.GROQ_API_KEY:
            logger.info("ai_skipped", reason="GROQ_API_KEY not set")
            return

        try:
            from app.database import AsyncSessionLocal
            from app.services.ai_service import AIService
            async with AsyncSessionLocal() as ai_db:
                await AIService(ai_db).analyze_scan_findings(scan_id)
        except Exception as exc:
            logger.warning("ai_analysis_skipped", reason=str(exc))
