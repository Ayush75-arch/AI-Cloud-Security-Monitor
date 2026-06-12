"""
CloudGuard-AI — Attack Path Analyzer
Identifies chained attack paths across findings.

Example paths:
  Public S3 → No encryption → Data exfiltration
  Open SSH → Wildcard IAM role on EC2 → Full account takeover
  Public EC2 → IAM role with S3 access → Sensitive bucket access

Returns structured attack chains for visualization in the dashboard.
"""
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Asset, Finding
from app.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class AttackNode:
    finding_id: str
    rule_id: str
    title: str
    severity: str
    asset_name: str
    asset_type: str
    description: str


@dataclass
class AttackPath:
    path_id: str
    title: str
    description: str
    overall_severity: str   # worst severity in chain
    steps: list[AttackNode] = field(default_factory=list)
    impact: str = ""
    likelihood: str = ""    # low / medium / high


# ── Attack path patterns ──────────────────────────────────────────────────────
# Each pattern defines a sequence of rule_ids that form a dangerous chain.
# If ALL rules in a pattern have open findings, an attack path is generated.

ATTACK_PATTERNS = [
    {
        "path_id": "AP-001",
        "title": "Internet Exposure → Lateral Movement → Data Exfiltration",
        "description": "An attacker exploits open SSH access to gain a foothold, then leverages overly permissive IAM to access sensitive data.",
        "rules": ["EC2-001", "IAM-001"],
        "impact": "Full account compromise. Attacker can access all S3 data, create backdoor IAM users, and pivot to other services.",
        "likelihood": "high",
    },
    {
        "path_id": "AP-002",
        "title": "Public S3 Bucket → Unencrypted Data → Sensitive Exposure",
        "description": "A publicly accessible S3 bucket without encryption exposes sensitive data to unauthenticated internet users.",
        "rules": ["S3-001", "S3-002"],
        "impact": "Direct data breach. All bucket contents readable by anyone with the bucket URL.",
        "likelihood": "high",
    },
    {
        "path_id": "AP-003",
        "title": "Open RDP → Ransomware Deployment → Data Destruction",
        "description": "Exposed RDP port allows brute-force or CVE exploitation, leading to ransomware deployment across the VPC.",
        "rules": ["EC2-002", "VPC-001"],
        "impact": "Full instance compromise, potential ransomware spread across VPC. No flow logs means zero forensic visibility.",
        "likelihood": "high",
    },
    {
        "path_id": "AP-004",
        "title": "Compromised IAM User → Privilege Escalation → Account Takeover",
        "description": "A phished IAM user without MFA and with wildcard permissions allows complete account takeover.",
        "rules": ["IAM-002", "IAM-001"],
        "impact": "Full AWS account takeover. Attacker can access all services, disable CloudTrail, and create persistence.",
        "likelihood": "high",
    },
    {
        "path_id": "AP-005",
        "title": "Stale Access Key → Data Exfiltration → Compliance Violation",
        "description": "A long-lived access key leaked via GitHub or logs enables silent data theft without MFA challenge.",
        "rules": ["IAM-003", "S3-001"],
        "impact": "Silent exfiltration of S3 data. No MFA barrier means key alone is sufficient for full API access.",
        "likelihood": "medium",
    },
    {
        "path_id": "AP-006",
        "title": "Public S3 → No Logging → Undetected Breach",
        "description": "A public bucket without access logging means a breach cannot be detected or scoped.",
        "rules": ["S3-001", "S3-004"],
        "impact": "Undetected data breach. Cannot determine what was accessed, by whom, or when — making breach notification impossible.",
        "likelihood": "medium",
    },
]


class AttackPathAnalyzer:
    """
    Analyzes open findings to identify dangerous attack chains.
    Returns paths sorted by severity for dashboard visualization.
    """

    def __init__(self, db: AsyncSession):
        self._db = db

    async def analyze(self, scan_id: str | None = None) -> list[AttackPath]:
        """
        Build attack paths from open findings.
        If scan_id provided, scoped to that scan; otherwise uses all open findings.
        """
        # Load all open findings with their assets
        query = (
            select(Finding, Asset)
            .join(Asset, Finding.asset_id == Asset.id)
            .where(Finding.status == "open")
        )
        if scan_id:
            query = query.where(Finding.scan_id == scan_id)

        result = await self._db.execute(query)
        rows = result.all()

        # Build lookup: rule_id → list of (finding, asset)
        rule_map: dict[str, list[tuple[Finding, Asset]]] = {}
        for finding, asset in rows:
            rule_map.setdefault(finding.rule_id, []).append((finding, asset))

        # Match patterns
        paths = []
        for pattern in ATTACK_PATTERNS:
            required_rules = pattern["rules"]

            # Check if ALL rules in pattern have open findings
            if not all(r in rule_map for r in required_rules):
                continue

            # Build attack nodes for each step
            steps = []
            for rule_id in required_rules:
                finding, asset = rule_map[rule_id][0]  # use first finding for this rule
                steps.append(AttackNode(
                    finding_id=finding.id,
                    rule_id=rule_id,
                    title=finding.title,
                    severity=finding.severity,
                    asset_name=asset.asset_name,
                    asset_type=asset.asset_type,
                    description=finding.description,
                ))

            # Overall severity = worst in chain
            sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            overall = sorted(steps, key=lambda s: sev_order.get(s.severity, 99))[0].severity

            paths.append(AttackPath(
                path_id=pattern["path_id"],  # type: ignore[arg-type]
                title=pattern["title"],  # type: ignore[arg-type]
                description=pattern["description"],  # type: ignore[arg-type]
                overall_severity=overall,
                steps=steps,
                impact=pattern["impact"],  # type: ignore[arg-type]
                likelihood=pattern["likelihood"],  # type: ignore[arg-type]
            ))

        # Sort by severity
        paths.sort(key=lambda p: sev_order.get(p.overall_severity, 99))
        logger.info("attack_paths_analyzed", paths_found=len(paths))
        return paths

    def to_dict(self, path: AttackPath) -> dict:
        return {
            "path_id": path.path_id,
            "title": path.title,
            "description": path.description,
            "overall_severity": path.overall_severity,
            "likelihood": path.likelihood,
            "impact": path.impact,
            "steps": [
                {
                    "finding_id": s.finding_id,
                    "rule_id": s.rule_id,
                    "title": s.title,
                    "severity": s.severity,
                    "asset_name": s.asset_name,
                    "asset_type": s.asset_type,
                    "description": s.description,
                }
                for s in path.steps
            ],
        }
