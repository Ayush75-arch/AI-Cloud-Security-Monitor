"""
CloudGuard-AI — Executive Report Generator
Generates beautiful HTML reports for C-suite and board meetings.
Includes: security score, compliance summary, top findings, attack paths,
trend charts, and executive summary narrative.
"""
import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select, func as sql_func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Asset, ComplianceResult, Finding, Scan
from app.utils.constants import FindingStatus
from app.utils.exceptions import ScanNotFoundError
from app.utils.logger import get_logger

logger = get_logger(__name__)


class ExecutiveReportService:

    def __init__(self, db: AsyncSession):
        self._db = db

    async def generate_html_report(self, scan_id: str | None = None) -> str:
        scan_data = await self._gather_data(scan_id)
        return self._render_html(scan_data)

    async def generate_json_report(self, scan_id: str | None = None) -> dict:
        return await self._gather_data(scan_id)

    async def _gather_data(self, scan_id: str | None = None) -> dict:
        if scan_id:
            result = await self._db.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one_or_none()
            if not scan:
                raise ScanNotFoundError(scan_id)
        else:
            result = await self._db.execute(
                select(Scan).order_by(Scan.created_at.desc()).limit(1)
            )
            scan = result.scalar_one_or_none()
            if not scan:
                return self._empty_report()

        findings_q = await self._db.execute(
            select(Finding).where(Finding.scan_id == scan.id).order_by(Finding.severity)
        )
        findings = findings_q.scalars().all()

        assets_q = await self._db.execute(select(Asset).where(Asset.scan_id == scan.id))
        assets = assets_q.scalars().all()

        compliance_q = await self._db.execute(
            select(ComplianceResult).where(ComplianceResult.scan_id == scan.id)
        )
        compliance = compliance_q.scalars().all()

        score = self._compute_security_score(scan)
        grade = self._score_to_grade(score)

        severity_distribution = {
            "critical": scan.critical_count,
            "high": scan.high_count,
            "medium": scan.medium_count,
            "low": scan.low_count,
        }

        top_findings = [
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity,
                "description": f.description[:200],
                "remediation": f.ai_remediation or "See AI analysis for details.",
            }
            for f in findings
            if f.severity in ("critical", "high")
        ][:10]

        attack_paths = []
        if findings:
            rule_ids = set(f.rule_id for f in findings)
            from app.services.attack_path_service import ATTACK_PATTERNS
            for pattern in ATTACK_PATTERNS:
                if all(r in rule_ids for r in pattern["rules"]):
                    attack_paths.append(pattern)

        compliance_summary = [
            {
                "framework": c.framework,
                "score": c.score,
                "grade": self._score_to_grade(c.score),
                "passed": c.passed_controls,
                "failed": c.failed_controls,
            }
            for c in compliance
        ]

        return {
            "report_metadata": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "report_type": "Executive Summary",
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
            },
            "security_score": {
                "score": score,
                "grade": grade,
                "assessment": self._grade_description(grade),
                "risk_level": "high" if score < 40 else ("medium" if score < 70 else "low"),
            },
            "findings_summary": {
                "total": len(findings),
                "open": sum(1 for f in findings if f.status == FindingStatus.OPEN),
                "severity_distribution": severity_distribution,
                "top_findings": top_findings,
            },
            "compliance_summary": compliance_summary,
            "attack_paths": [
                {
                    "path_id": ap["path_id"],
                    "title": ap["title"],
                    "description": ap["description"],
                    "impact": ap.get("impact", ""),
                    "likelihood": ap.get("likelihood", "medium"),
                }
                for ap in attack_paths
            ],
            "assets": {
                "total": len(assets),
                "by_type": self._count_by_type(assets),
            },
            "narrative": self._generate_narrative(scan, score, grade, severity_distribution, compliance_summary),
        }

    def _compute_security_score(self, scan: Scan) -> float:
        if not scan.total_findings:
            return 100.0
        risk_raw = (scan.critical_count * 10 + scan.high_count * 7 + scan.medium_count * 4 + scan.low_count * 1)
        risk_score = min((risk_raw / scan.total_findings) * 10, 100.0)
        return max(0, round(100.0 - risk_score, 1))

    def _score_to_grade(self, score: float) -> str:
        if score >= 95: return "A+"
        if score >= 90: return "A"
        if score >= 85: return "A-"
        if score >= 80: return "B+"
        if score >= 75: return "B"
        if score >= 70: return "B-"
        if score >= 65: return "C+"
        if score >= 60: return "C"
        if score >= 55: return "C-"
        if score >= 40: return "D"
        return "F"

    def _grade_description(self, grade: str) -> str:
        descriptions = {
            "A+": "Excellent security posture — minimal risk exposure.",
            "A": "Strong security posture with minor improvements needed.",
            "A-": "Good security posture with some areas to address.",
            "B+": "Above-average security posture.",
            "B": "Moderate security posture with notable risks.",
            "B-": "Adequate security but significant improvements needed.",
            "C+": "Below-average security posture requires attention.",
            "C": "Weak security posture — several critical gaps exist.",
            "C-": "Poor security posture requiring immediate action.",
            "D": "Critical security gaps — urgent remediation required.",
            "F": "Severe security risk — immediate executive action needed.",
        }
        return descriptions.get(grade, "Security posture needs assessment.")

    def _generate_narrative(self, scan, score, grade, severity, compliance) -> str:
        total = severity["critical"] + severity["high"] + severity["medium"] + severity["low"]
        critical = severity["critical"]
        high = severity["high"]

        avg_compliance = round(sum(c["score"] for c in compliance) / len(compliance), 1) if compliance else 0.0

        narrative = f"""
Your cloud security posture currently scores {score} out of 100, earning a grade of {grade}. 
This assessment is based on a comprehensive scan of {scan.total_findings} potential issues across 
{len(scan.services)} AWS services in the {scan.region} region.

The scan identified {critical} critical and {high} high-severity findings that require immediate attention. 
The average compliance score across all frameworks is {avg_compliance}%.

Key concerns include:"""
        if critical > 0:
            narrative += f"\n- {critical} critical severity issues that pose immediate security risk"
        if high > 0:
            narrative += f"\n- {high} high severity issues that require prioritized remediation"

        narrative += f"\n\nWe recommend prioritizing the remediation of critical and high-severity findings, "
        narrative += f"implementing automated remediation playbooks where possible, and scheduling regular scans "
        narrative += f"to track security posture improvement over time."

        return narrative

    def _count_by_type(self, assets: list) -> dict:
        counts = {}
        for a in assets:
            counts[a.asset_type] = counts.get(a.asset_type, 0) + 1
        return counts

    def _empty_report(self) -> dict:
        return {
            "report_metadata": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "report_type": "Executive Summary",
                "version": "1.0.0",
            },
            "message": "No scan data available. Run a scan first.",
            "security_score": {"score": 0, "grade": "N/A", "assessment": "No data available."},
        }

    def _render_html(self, data: dict) -> str:
        score = data.get("security_score", {})
        grade = score.get("grade", "N/A")
        score_val = score.get("score", 0)
        findings = data.get("findings_summary", {})
        sev = findings.get("severity_distribution", {})
        compliance = data.get("compliance_summary", [])
        paths = data.get("attack_paths", [])
        assets = data.get("assets", {})
        narrative = data.get("narrative", "")

        compliance_rows = "".join(
            f"<tr><td>{c['framework']}</td><td>{c['score']}%</td><td>{c['grade']}</td>"
            f"<td>{c['passed']} passed / {c['failed']} failed</td></tr>"
            for c in compliance
        )

        paths_rows = "".join(
            f"<tr><td>{p['path_id']}</td><td>{p['title']}</td>"
            f"<td>{p['likelihood'].upper()}</td><td>{p.get('impact', '')[:150]}</td></tr>"
            for p in paths
        )

        top_findings_rows = ""
        for f in findings.get("top_findings", []):
            sev_badge = f'<span class="sev-{f["severity"]}">{f["severity"].upper()}</span>'
            top_findings_rows += f"""
            <div class="finding-card">
                <div class="finding-header">
                    {sev_badge} <strong>{f['rule_id']}:</strong> {f['title']}
                </div>
                <p>{f['description'][:200]}</p>
            </div>"""

        color = "#22c55e" if grade in ("A+", "A", "A-") else "#eab308" if grade in ("B+", "B", "B-", "C+") else "#ef4444"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CloudGuard-AI Executive Report</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #e2e8f0; line-height: 1.6; }}
  .container {{ max-width: 1000px; margin: 0 auto; padding: 40px 20px; }}
  .header {{ text-align: center; padding: 40px 0; border-bottom: 1px solid #1e293b; margin-bottom: 40px; }}
  .header h1 {{ font-size: 2.5em; background: linear-gradient(135deg, #818cf8, #22d3ee); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
  .header .subtitle {{ color: #94a3b8; margin-top: 8px; }}
  .score-card {{ background: linear-gradient(135deg, #1e293b, #334155); border-radius: 24px; padding: 40px; text-align: center; margin-bottom: 40px; }}
  .grade {{ font-size: 5em; font-weight: 800; color: {color}; }}
  .score {{ font-size: 1.5em; color: #94a3b8; margin-top: 8px; }}
  .assessment {{ font-size: 1.1em; color: #cbd5e1; margin-top: 12px; }}
  .section {{ background: #1e293b; border-radius: 16px; padding: 30px; margin-bottom: 24px; }}
  .section h2 {{ font-size: 1.3em; color: #818cf8; margin-bottom: 20px; border-bottom: 1px solid #334155; padding-bottom: 12px; }}
  .severity-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin: 20px 0; }}
  .severity-box {{ padding: 20px; border-radius: 12px; text-align: center; }}
  .sev-critical {{ background: rgba(239, 68, 68, 0.15); border: 1px solid #ef4444; }}
  .sev-high {{ background: rgba(249, 115, 22, 0.15); border: 1px solid #f97316; }}
  .sev-medium {{ background: rgba(234, 179, 8, 0.15); border: 1px solid #eab308; }}
  .sev-low {{ background: rgba(34, 197, 94, 0.15); border: 1px solid #22c55e; }}
  .severity-box .count {{ font-size: 2em; font-weight: 700; }}
  .severity-box .label {{ font-size: 0.85em; margin-top: 4px; text-transform: uppercase; letter-spacing: 1px; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th, td {{ padding: 12px 16px; text-align: left; border-bottom: 1px solid #334155; }}
  th {{ color: #94a3b8; font-weight: 500; text-transform: uppercase; font-size: 0.8em; letter-spacing: 1px; }}
  .finding-card {{ background: #0f172a; border: 1px solid #334155; border-radius: 12px; padding: 16px; margin-bottom: 12px; }}
  .finding-header {{ margin-bottom: 8px; }}
  .finding-header .sev-critical {{ color: #ef4444; }}
  .finding-header .sev-high {{ color: #f97316; }}
  .finding-header .sev-medium {{ color: #eab308; }}
  .finding-header .sev-low {{ color: #22c55e; }}
  .finding-card p {{ color: #94a3b8; font-size: 0.9em; }}
  .narrative {{ background: #334155; border-radius: 12px; padding: 20px; color: #cbd5e1; line-height: 1.8; margin-top: 20px; }}
  .footer {{ text-align: center; padding: 40px 0; color: #475569; font-size: 0.85em; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75em; font-weight: 600; }}
  .badge-high {{ background: rgba(249, 115, 22, 0.2); color: #f97316; }}
  .badge-medium {{ background: rgba(234, 179, 8, 0.2); color: #eab308; }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>CloudGuard-AI</h1>
    <p class="subtitle">Executive Security Report — {data.get("report_metadata", {}).get("generated_at", "")[:10]}</p>
  </div>

  <div class="score-card">
    <div class="grade">{grade}</div>
    <div class="score">Security Score: {score_val}/100</div>
    <div class="assessment">{score.get("assessment", "")}</div>
  </div>

  <div class="section">
    <h2>Executive Summary</h2>
    <div class="narrative">{narrative}</div>
  </div>

  <div class="section">
    <h2>Finding Severity Distribution</h2>
    <div class="severity-grid">
      <div class="severity-box sev-critical"><div class="count">{sev.get("critical", 0)}</div><div class="label">Critical</div></div>
      <div class="severity-box sev-high"><div class="count">{sev.get("high", 0)}</div><div class="label">High</div></div>
      <div class="severity-box sev-medium"><div class="count">{sev.get("medium", 0)}</div><div class="label">Medium</div></div>
      <div class="severity-box sev-low"><div class="count">{sev.get("low", 0)}</div><div class="label">Low</div></div>
    </div>
    <p style="color: #94a3b8; text-align: center; margin-top: 12px;">
      Total: {findings.get("total", 0)} findings ({findings.get("open", 0)} open)
    </p>
  </div>

  <div class="section">
    <h2>Top Critical & High Findings</h2>
    {top_findings_rows if top_findings_rows else '<p style="color: #94a3b8;">No critical or high findings.</p>'}
  </div>

  <div class="section">
    <h2>Compliance Overview</h2>
    <table>
      <thead><tr><th>Framework</th><th>Score</th><th>Grade</th><th>Details</th></tr></thead>
      <tbody>{compliance_rows if compliance_rows else '<tr><td colspan="4">No compliance data available.</td></tr>'}</tbody>
    </table>
  </div>

  <div class="section">
    <h2>Attack Paths Detected</h2>
    <table>
      <thead><tr><th>Path ID</th><th>Title</th><th>Likelihood</th><th>Potential Impact</th></tr></thead>
      <tbody>{paths_rows if paths_rows else '<tr><td colspan="4">No attack paths detected.</td></tr>'}</tbody>
    </table>
  </div>

  <div class="section">
    <h2>Asset Inventory</h2>
    <p style="color: #94a3b8;">Total assets scanned: {assets.get("total", 0)}</p>
    <table>
      <thead><tr><th>Type</th><th>Count</th></tr></thead>
      <tbody>
        {''.join(f'<tr><td>{k}</td><td>{v}</td></tr>' for k, v in assets.get("by_type", {}).items())}
      </tbody>
    </table>
  </div>

  <div class="section">
    <h2>Recommendations</h2>
    <ol style="color: #cbd5e1; padding-left: 20px;">
      <li style="margin-bottom: 8px;">Prioritize remediation of critical and high-severity findings immediately.</li>
      <li style="margin-bottom: 8px;">Enable automated remediation playbooks for repeatable fixes.</li>
      <li style="margin-bottom: 8px;">Schedule weekly scans to track security posture improvement.</li>
      <li style="margin-bottom: 8px;">Set up Slack/Email notifications for critical findings in real-time.</li>
      <li style="margin-bottom: 8px;">Conduct a compliance gap analysis for underperforming frameworks.</li>
    </ol>
  </div>

  <div class="footer">
    <p>Generated by CloudGuard-AI | {data.get("report_metadata", {}).get("generated_at", "")}</p>
    <p>Account: {data.get("scan", {}).get("account_id", "N/A")} | Region: {data.get("scan", {}).get("region", "N/A")}</p>
  </div>
</div>
</body>
</html>"""
