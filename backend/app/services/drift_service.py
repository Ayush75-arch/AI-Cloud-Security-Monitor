"""
CloudGuard-AI — Compliance Drift Detector
Real-time compliance drift monitoring between scans.
Detects when previously compliant resources drift out of compliance,
and when previously fixed findings reappear.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select, func as sql_func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import ComplianceResult, Finding, Scan
from app.utils.constants import FindingStatus, Severity
from app.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class DriftEvent:
    event_type: str  # "compliance_drift", "finding_reappearance", "new_critical"
    severity: str
    title: str
    description: str
    timestamp: str
    scan_id: str
    framework: str = ""
    score_change: float = 0.0


class DriftDetector:
    """
    Compares the latest two scans to detect compliance drift.
    Alerts when:
    - Compliance score drops by >5%
    - Previously resolved findings reappear
    - New critical/high findings appear
    """

    def __init__(self, db: AsyncSession):
        self._db = db

    async def detect(self) -> list[dict]:
        events: list[DriftEvent] = []

        scans_q = await self._db.execute(
            select(Scan)
            .where(Scan.status == "completed")
            .order_by(Scan.created_at.desc())
            .limit(2)
        )
        scans = scans_q.scalars().all()

        if len(scans) < 2:
            return [{"message": "Need at least 2 completed scans for drift detection."}]

        current, previous = scans[0], scans[1]

        drift = await self._check_compliance_drift(current.id, previous.id)
        events.extend(drift)

        reappearances = await self._check_finding_reappearance(current.id, previous.id)
        events.extend(reappearances)

        new_criticals = await self._check_new_critical(current.id, previous.id)
        events.extend(new_criticals)

        return self._format_events(events)

    async def _check_compliance_drift(self, current_id: str, previous_id: str) -> list[DriftEvent]:
        events = []

        curr_q = await self._db.execute(
            select(ComplianceResult).where(ComplianceResult.scan_id == current_id)
        )
        curr_results = {r.framework: r for r in curr_q.scalars().all()}

        prev_q = await self._db.execute(
            select(ComplianceResult).where(ComplianceResult.scan_id == previous_id)
        )
        prev_results = {r.framework: r for r in prev_q.scalars().all()}

        for framework, curr in curr_results.items():
            prev = prev_results.get(framework)
            if prev:
                change = round(curr.score - prev.score, 1)
                if change < -5.0:
                    events.append(DriftEvent(
                        event_type="compliance_drift",
                        severity="high",
                        title=f"Compliance Score Dropped: {framework}",
                        description=f"{framework} compliance score dropped from {prev.score}% to {curr.score}% ({change}% change).",
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        scan_id=current_id,
                        framework=framework,
                        score_change=change,
                    ))
                elif change < -2.0:
                    events.append(DriftEvent(
                        event_type="compliance_drift",
                        severity="medium",
                        title=f"Minor Compliance Dip: {framework}",
                        description=f"{framework} compliance score dropped from {prev.score}% to {curr.score}% (-{abs(change)}%).",
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        scan_id=current_id,
                        framework=framework,
                        score_change=change,
                    ))

        return events

    async def _check_finding_reappearance(self, current_id: str, previous_id: str) -> list[DriftEvent]:
        events = []

        prev_q = await self._db.execute(
            select(Finding).where(
                Finding.scan_id == previous_id,
                Finding.status == FindingStatus.RESOLVED,
                Finding.fingerprint.isnot(None),
            )
        )
        prev_fingerprints = {f.fingerprint for f in prev_q.scalars().all() if f.fingerprint}

        if not prev_fingerprints:
            return events

        curr_q = await self._db.execute(
            select(Finding).where(
                Finding.scan_id == current_id,
                Finding.status == FindingStatus.OPEN,
                Finding.fingerprint.in_(prev_fingerprints),
            )
        )

        for finding in curr_q.scalars().all():
            events.append(DriftEvent(
                event_type="finding_reappearance",
                severity=finding.severity,
                title=f"Finding Reappeared: {finding.rule_id}",
                description=f"A previously resolved finding ({finding.rule_id}: {finding.title}) has reappeared on {finding.asset_id}.",
                timestamp=datetime.now(timezone.utc).isoformat(),
                scan_id=current_id,
            ))

        return events

    async def _check_new_critical(self, current_id: str, previous_id: str) -> list[DriftEvent]:
        events = []

        prev_q = await self._db.execute(
            select(Finding.rule_id, Finding.asset_id).where(Finding.scan_id == previous_id)
        )
        prev_pairs = {(r.rule_id, r.asset_id) for r in prev_q.all()}

        curr_q = await self._db.execute(
            select(Finding).where(
                Finding.scan_id == current_id,
                Finding.severity.in_([Severity.CRITICAL, Severity.HIGH]),
            )
        )

        for finding in curr_q.scalars().all():
            pair = (finding.rule_id, finding.asset_id)
            if pair not in prev_pairs:
                events.append(DriftEvent(
                    event_type="new_critical",
                    severity=finding.severity,
                    title=f"New {finding.severity.upper()}: {finding.rule_id}",
                    description=f"New finding detected on {finding.asset_id}: {finding.title}",
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    scan_id=current_id,
                ))

        return events

    def _format_events(self, events: list[DriftEvent]) -> list[dict]:
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        events.sort(key=lambda e: sev_order.get(e.severity, 99))

        return [
            {
                "event_type": e.event_type,
                "severity": e.severity,
                "title": e.title,
                "description": e.description,
                "timestamp": e.timestamp,
                "scan_id": e.scan_id,
                "framework": e.framework,
                "score_change": e.score_change,
            }
            for e in events
        ]
