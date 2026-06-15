"""
CloudGuard-AI — Cloud Security Graph Engine
Builds a directed graph of your entire cloud infrastructure showing:
- Resource relationships (IAM roles attached to EC2, S3 buckets accessed by Lambda, etc.)
- Attack paths as graph traversals
- Security hotspots (most connected risky nodes)
- Blast radius visualization
Inspired by Neo4j graph databases — runs in-memory.
"""
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Asset, Finding
from app.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class GraphNode:
    id: str
    label: str
    type: str
    severity: str = "info"
    findings_count: int = 0
    properties: dict = field(default_factory=dict)


@dataclass
class GraphEdge:
    source: str
    target: str
    label: str
    type: str  # "iam_trust", "network_access", "data_access", "containment"
    risk: str = "low"


@dataclass
class SecurityGraph:
    nodes: list[GraphNode] = field(default_factory=list)
    edges: list[GraphEdge] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "nodes": [
                {
                    "id": n.id,
                    "label": n.label,
                    "type": n.type,
                    "severity": n.severity,
                    "findings_count": n.findings_count,
                    "properties": n.properties,
                }
                for n in self.nodes
            ],
            "edges": [
                {
                    "source": e.source,
                    "target": e.target,
                    "label": e.label,
                    "type": e.type,
                    "risk": e.risk,
                }
                for e in self.edges
            ],
            "stats": {
                "total_nodes": len(self.nodes),
                "total_edges": len(self.edges),
                "high_risk_nodes": sum(1 for n in self.nodes if n.severity in ("critical", "high")),
            },
        }


class GraphBuilder:
    """
    Builds a SecurityGraph from scan results.
    Discovers relationships between assets based on:
    1. IAM roles attached to EC2/Lambda
    2. Security groups applied to EC2/RDS
    3. Bucket policies referencing IAM principals
    4. VPC subnets containing resources
    5. Findings grouping multiple assets
    """

    def __init__(self, db: AsyncSession):
        self._db = db
        self._assets: dict[str, Asset] = {}
        self._findings: dict[str, list[Finding]] = {}
        self._graph = SecurityGraph()

    async def build(self, scan_id: str | None = None) -> SecurityGraph:
        await self._load_data(scan_id)
        self._create_nodes()
        self._create_edges()
        self._enrich_with_findings()
        logger.info("graph_built", nodes=len(self._graph.nodes), edges=len(self._graph.edges))
        return self._graph

    async def _load_data(self, scan_id: str | None = None):
        query = select(Asset)
        if scan_id:
            query = query.where(Asset.scan_id == scan_id)
        result = await self._db.execute(query)
        for asset in result.scalars().all():
            self._assets[asset.id] = asset

        finding_query = select(Finding)
        if scan_id:
            finding_query = finding_query.where(Finding.scan_id == scan_id)
        f_result = await self._db.execute(finding_query)
        for finding in f_result.scalars().all():
            self._findings.setdefault(finding.asset_id, []).append(finding)

    def _create_nodes(self):
        for asset_id, asset in self._assets.items():
            findings = self._findings.get(asset_id, [])
            worst = "info"
            sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            for f in findings:
                if sev_order.get(f.severity, 99) < sev_order.get(worst, 99):
                    worst = f.severity

            props = {}
            rc = asset.raw_config or {}
            if asset.asset_type == "ec2_instance":
                props["instance_type"] = rc.get("InstanceType", "")
                props["vpc_id"] = rc.get("VpcId", "")
            elif asset.asset_type in ("s3_bucket",):
                props["public_access"] = rc.get("PublicAccessBlockConfiguration") is None
            elif asset.asset_type == "security_group":
                props["group_name"] = rc.get("GroupName", "")
            elif asset.asset_type == "lambda_function":
                props["runtime"] = rc.get("Runtime", "")
                props["timeout"] = rc.get("Timeout", 0)
            elif asset.asset_type == "rds_instance":
                props["engine"] = rc.get("Engine", "")
                props["publicly_accessible"] = rc.get("PubliclyAccessible", False)
            elif asset.asset_type == "kms_key":
                props["key_manager"] = rc.get("KeyManager", "")
                props["rotation"] = rc.get("KeyRotationEnabled", False)

            self._graph.nodes.append(GraphNode(
                id=asset.asset_id,
                label=asset.asset_name,
                type=asset.asset_type,
                severity=worst,
                findings_count=len(findings),
                properties=props,
            ))

    def _create_edges(self):
        for asset_id, asset in self._assets.items():
            rc = asset.raw_config or {}

            if asset.asset_type == "ec2_instance":
                sg_ids = [sg.get("GroupId", "") for sg in rc.get("SecurityGroups", [])]
                for sg_id in sg_ids:
                    self._add_edge(asset.asset_id, sg_id, "uses security group", "containment", "medium")

                iam_profile = rc.get("IamInstanceProfile", {})
                arn = iam_profile.get("Arn", "")
                if arn:
                    self._add_edge(asset.asset_id, arn, "assumes IAM role", "iam_trust", "high")

            elif asset.asset_type == "lambda_function":
                vpc_config = rc.get("VpcConfig", {})
                for sg_id in vpc_config.get("SecurityGroupIds", []):
                    self._add_edge(asset.asset_id, sg_id, "uses security group", "containment", "medium")
                for subnet_id in vpc_config.get("SubnetIds", []):
                    self._add_edge(asset.asset_id, subnet_id, "deployed in subnet", "containment", "low")

                role_arn = rc.get("Role", "")
                if role_arn:
                    self._add_edge(asset.asset_id, role_arn, "uses IAM role", "iam_trust", "high")

            elif asset.asset_type in ("security_group",):
                for perm in rc.get("IpPermissions", []):
                    for ip_range in perm.get("IpRanges", []):
                        cidr = ip_range.get("CidrIp", "")
                        if cidr == "0.0.0.0/0":
                            self._add_edge(
                                asset.asset_id, "internet",
                                f"exposed port {perm.get('FromPort', 'any')}", "network_access", "critical"
                            )

            elif asset.asset_type == "rds_instance":
                for sg in rc.get("VpcSecurityGroups", []):
                    sg_id = sg.get("VpcSecurityGroupId", "")
                    if sg_id:
                        self._add_edge(asset.asset_id, sg_id, "protected by", "containment", "medium")

            elif asset.asset_type == "iam_role":
                assume_role = rc.get("AssumeRolePolicyDocument", {})
                principals = self._extract_principals(assume_role)
                for principal in principals:
                    self._add_edge(principal, asset.asset_id, "can assume role", "iam_trust", "high")

            elif asset.asset_type == "iam_policy":
                for attached in rc.get("AttachedPolicies", []):
                    principal = attached.get("PrincipalArn", "") or attached.get("PolicyName", "")
                    if principal:
                        self._add_edge(asset.asset_id, principal, "attached to", "iam_trust", "high")

    def _extract_principals(self, policy_doc: dict) -> list[str]:
        principals = []
        statements = policy_doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        for stmt in statements:
            principal = stmt.get("Principal", {})
            if isinstance(principal, dict):
                aws = principal.get("AWS", [])
                if isinstance(aws, str):
                    aws = [aws]
                for a in aws:
                    if a != "*":
                        principals.append(a)
                service = principal.get("Service", [])
                if isinstance(service, str):
                    service = [service]
                for s in service:
                    principals.append(f"service:{s}")
        return principals

    def _add_edge(self, source: str, target: str, label: str, etype: str, risk: str = "low"):
        if source and target:
            self._graph.edges.append(GraphEdge(source=source, target=target, label=label, type=etype, risk=risk))

    def _enrich_with_findings(self):
        for node in self._graph.nodes:
            node.findings_count = sum(
                1 for f in self._findings.values()
                for finding in f
                if any(a.asset_id == node.id for a in self._assets.values())
            )

    async def get_attack_paths_graph(self, scan_id: str | None = None) -> list[dict]:
        """Generate directed attack paths as graph traversals."""
        await self.build(scan_id)

        paths = []
        for node in self._graph.nodes:
            if node.severity not in ("critical", "high"):
                continue

            if node.type == "security_group" and node.properties.get("group_name", ""):
                exposed_ports = []
                for edge in self._graph.edges:
                    if edge.source == node.id and edge.target == "internet":
                        exposed_ports.append(edge.label)

                targets = []
                for edge in self._graph.edges:
                    if edge.target == node.id and edge.type == "containment":
                        for e2 in self._graph.edges:
                            if e2.source == edge.source and e2.type == "iam_trust":
                                targets.append(e2.target)

                if exposed_ports and targets:
                    paths.append({
                        "entry_point": node.id,
                        "entry_label": node.label,
                        "via": exposed_ports,
                        "target": targets,
                        "severity": node.severity,
                        "type": "internet_exposure_to_privilege_escalation",
                    })

        return paths

    def get_hotspot_nodes(self, top_n: int = 10) -> list[dict]:
        """Find the most connected risky nodes."""
        edge_count: dict[str, int] = {}
        for edge in self._graph.edges:
            edge_count[edge.source] = edge_count.get(edge.source, 0) + 1
            edge_count[edge.target] = edge_count.get(edge.target, 0) + 1

        scored = []
        for node in self._graph.nodes:
            if node.severity in ("critical", "high", "medium"):
                connectivity = edge_count.get(node.id, 0)
                risk_score = (connectivity * 2) + ({"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}.get(node.severity, 0))
                scored.append({
                    "node_id": node.id,
                    "label": node.label,
                    "type": node.type,
                    "severity": node.severity,
                    "connectivity": connectivity,
                    "risk_score": risk_score,
                    "findings_count": node.findings_count,
                })

        scored.sort(key=lambda x: x["risk_score"], reverse=True)  # type: ignore[arg-type, return-value]
        return scored[:top_n]
