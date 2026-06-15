"""
CloudGuard-AI — Compliance Service
Computes per-framework compliance scores based on rule findings.
Maps rule_id → compliance controls → pass/fail per framework.
"""
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import ComplianceResult
from app.rules.base_rule import RuleFinding
from app.rules.engine import ALL_RULES
from app.utils.constants import ComplianceFramework
from app.utils.logger import get_logger

logger = get_logger(__name__)

# Build control registry: framework → set of all control IDs from rules
_ALL_CONTROLS: dict[str, set[str]] = {f.value: set() for f in ComplianceFramework}
for _r in ALL_RULES:
    if _r.compliance_mappings:
        for fw, control in _r.compliance_mappings.items():
            if fw in _ALL_CONTROLS:
                _ALL_CONTROLS[fw].add(control)


class ComplianceService:

    def __init__(self, db: AsyncSession):
        self._db = db

    async def compute_and_save(
        self, scan_id: str, findings: list[RuleFinding]
    ) -> list[ComplianceResult]:
        """
        Compute compliance scores per framework and persist.
        Score = (passed_controls / total_controls) * 100
        """
        results = []
        for framework in ComplianceFramework:
            fw_val = framework.value
            all_controls = _ALL_CONTROLS.get(fw_val, set())
            if not all_controls:
                continue

            # Failed controls = controls mapped to a triggered finding
            failed_controls: set[str] = set()
            control_details: dict[str, dict] = {}

            for finding in findings:
                control = finding.compliance_mappings.get(fw_val)
                if control:
                    failed_controls.add(control)
                    control_details[control] = {
                        "status": "FAIL",
                        "rule_id": finding.rule_id,
                        "title": finding.title,
                        "severity": finding.severity,
                    }

            passed = all_controls - failed_controls
            for ctrl in passed:
                control_details[ctrl] = {"status": "PASS"}

            score = (len(passed) / len(all_controls)) * 100 if all_controls else 100.0

            cr = ComplianceResult(
                scan_id=scan_id,
                framework=fw_val,
                score=round(score, 1),
                passed_controls=len(passed),
                failed_controls=len(failed_controls),
                control_details=control_details,
            )
            self._db.add(cr)
            results.append(cr)

            logger.info(
                "compliance_computed",
                framework=fw_val,
                score=score,
                passed=len(passed),
                failed=len(failed_controls),
            )

        await self._db.flush()
        return results
