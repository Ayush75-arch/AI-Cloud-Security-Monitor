"""
CloudGuard-AI — Report Export Service
Generates CSV and JSON reports for findings and compliance data.
"""
import csv
import io
import json
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Asset, ComplianceResult, Finding, Scan
from app.utils.constants import FindingStatus
from app.utils.exceptions import ScanNotFoundError
from app.utils.logger import get_logger

logger = get_logger(__name__)


class ReportService:

    def __init__(self, db: AsyncSession):
        self._db = db

    async def export_findings_csv(self, scan_id: str | None = None) -> str:
        query = select(Finding)
        if scan_id:
            query = query.where(Finding.scan_id == scan_id)
        query = query.order_by(Finding.created_at.desc())

        result = await self._db.execute(query)
        findings = result.scalars().all()

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "ID", "Rule ID", "Title", "Severity", "Status",
            "Asset ID", "Description", "Compliance Mappings",
            "AI Explanation", "AI Attack Scenario", "AI Remediation",
            "Created At",
        ])

        for f in findings:
            writer.writerow([
                f.id, f.rule_id, f.title, f.severity, f.status,
                f.asset_id, f.description,
                json.dumps(f.compliance_mappings),
                f.ai_explanation or "",
                f.ai_attack_scenario or "",
                f.ai_remediation or "",
                f.created_at.isoformat() if f.created_at else "",
            ])

        return output.getvalue()

    async def export_compliance_csv(self, scan_id: str | None = None) -> str:
        query = select(ComplianceResult)
        if scan_id:
            query = query.where(ComplianceResult.scan_id == scan_id)
        query = query.order_by(ComplianceResult.computed_at.desc())

        result = await self._db.execute(query)
        rows = result.scalars().all()

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Scan ID", "Framework", "Score", "Passed", "Failed", "Computed At"])

        for r in rows:
            writer.writerow([
                r.scan_id, r.framework, r.score,
                r.passed_controls, r.failed_controls,
                r.computed_at.isoformat() if r.computed_at else "",
            ])

        return output.getvalue()

    async def export_findings_json(self, scan_id: str | None = None) -> str:
        query = select(Finding)
        if scan_id:
            query = query.where(Finding.scan_id == scan_id)
        query = query.order_by(Finding.created_at.desc())

        result = await self._db.execute(query)
        findings = result.scalars().all()

        data = []
        for f in findings:
            data.append({
                "id": f.id,
                "scan_id": f.scan_id,
                "rule_id": f.rule_id,
                "title": f.title,
                "description": f.description,
                "severity": f.severity,
                "status": f.status,
                "compliance_mappings": f.compliance_mappings,
                "ai_explanation": f.ai_explanation,
                "ai_attack_scenario": f.ai_attack_scenario,
                "ai_remediation": f.ai_remediation,
                "created_at": f.created_at.isoformat() if f.created_at else None,
            })

        return json.dumps(data, indent=2, default=str)

    async def export_full_report_json(self, scan_id: str) -> str:
        scan_q = await self._db.execute(select(Scan).where(Scan.id == scan_id))
        scan = scan_q.scalar_one_or_none()
        if not scan:
            raise ScanNotFoundError(scan_id)

        assets_q = await self._db.execute(select(Asset).where(Asset.scan_id == scan_id))
        assets = assets_q.scalars().all()

        findings_q = await self._db.execute(
            select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.severity)
        )
        findings = findings_q.scalars().all()

        compliance_q = await self._db.execute(
            select(ComplianceResult).where(ComplianceResult.scan_id == scan_id)
        )
        compliance = compliance_q.scalars().all()

        report = {
            "report_metadata": {
                "generated_at": datetime.utcnow().isoformat(),
                "source": "CloudGuard-AI",
                "version": "1.0.0",
            },
            "scan": {
                "id": scan.id,
                "account_id": scan.account_id,
                "region": scan.region,
                "services": scan.services,
                "status": scan.status,
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                "total_findings": scan.total_findings,
                "critical_count": scan.critical_count,
                "high_count": scan.high_count,
                "medium_count": scan.medium_count,
                "low_count": scan.low_count,
            },
            "assets": [
                {
                    "id": a.id,
                    "type": a.asset_type,
                    "arn": a.asset_id,
                    "name": a.asset_name,
                    "region": a.region,
                }
                for a in assets
            ],
            "findings": [
                {
                    "id": f.id,
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity,
                    "status": f.status,
                    "compliance_mappings": f.compliance_mappings,
                    "ai_explanation": f.ai_explanation,
                    "ai_attack_scenario": f.ai_attack_scenario,
                    "ai_remediation": f.ai_remediation,
                }
                for f in findings
            ],
            "compliance": [
                {
                    "framework": c.framework,
                    "score": c.score,
                    "passed": c.passed_controls,
                    "failed": c.failed_controls,
                    "controls": c.control_details,
                }
                for c in compliance
            ],
            "summary": {
                "overall_compliance_score": round(
                    sum(c.score for c in compliance) / len(compliance), 1
                ) if compliance else 0.0,
                "total_assets": len(assets),
                "total_findings": len(findings),
                "open_findings": sum(1 for f in findings if f.status == FindingStatus.OPEN),
                "critical_findings": scan.critical_count,
                "high_findings": scan.high_count,
            },
        }

        return json.dumps(report, indent=2, default=str)
