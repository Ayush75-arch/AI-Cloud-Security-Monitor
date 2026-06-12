"""
CloudGuard-AI — Test Suite
Run: pytest tests/ -v

Uses an in-memory SQLite DB — no external services needed.
"""
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.database import engine, Base


@pytest_asyncio.fixture(autouse=True)
async def setup_db():
    """Create all tables before each test, drop after."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture
async def client():
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test"
    ) as c:
        yield c


# ── Health ────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_health(client):
    res = await client.get("/health")
    assert res.status_code == 200
    assert res.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_api_health(client):
    res = await client.get("/api/v1/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert "version" in data


# ── Auth ──────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_login_success(client):
    res = await client.post("/api/v1/auth/login", json={
        "username": "admin",
        "password": "cloudguard123"
    })
    assert res.status_code == 200
    data = res.json()["data"]
    assert "access_token" in data
    assert data["token_type"] == "bearer"


@pytest.mark.asyncio
async def test_login_wrong_password(client):
    res = await client.post("/api/v1/auth/login", json={
        "username": "admin",
        "password": "wrongpassword"
    })
    assert res.status_code == 401


@pytest.mark.asyncio
async def test_me_requires_auth(client):
    res = await client.get("/api/v1/auth/me")
    assert res.status_code == 401


@pytest.mark.asyncio
async def test_me_with_token(client):
    login = await client.post("/api/v1/auth/login", json={
        "username": "admin", "password": "cloudguard123"
    })
    token = login.json()["data"]["access_token"]
    res = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    assert res.json()["data"]["username"] == "admin"


# ── Scans ─────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_list_scans_empty(client):
    res = await client.get("/api/v1/scans")
    assert res.status_code == 200
    assert res.json()["data"] == []


@pytest.mark.asyncio
async def test_create_scan(client, monkeypatch):
    import asyncio

    def close_background_task(coro, *args, **kwargs):
        coro.close()
        task = asyncio.get_running_loop().create_future()
        task.set_result(None)
        return task

    monkeypatch.setattr(asyncio, "create_task", close_background_task)

    res = await client.post("/api/v1/scans", json={
        "account_id": "123456789012",
        "region": "us-east-1",
        "services": ["s3", "iam"],
    })
    assert res.status_code == 202
    data = res.json()["data"]
    assert data["account_id"] == "123456789012"
    assert data["status"] == "pending"
    assert "id" in data


@pytest.mark.asyncio
async def test_get_scan_not_found(client):
    res = await client.get("/api/v1/scans/nonexistent-id")
    assert res.status_code == 404
    assert res.json()["errors"][0]["code"] == "SCAN_NOT_FOUND"


# ── Findings ──────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_list_findings_empty(client):
    res = await client.get("/api/v1/findings")
    assert res.status_code == 200
    assert res.json()["data"] == []


@pytest.mark.asyncio
async def test_dashboard_stats_empty(client):
    res = await client.get("/api/v1/dashboard/stats")
    assert res.status_code == 200
    data = res.json()["data"]
    assert data["total_findings"] == 0
    assert data["total_assets"] == 0
    assert data["risk_score"] == 0.0


# ── Compliance ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_compliance_empty(client):
    res = await client.get("/api/v1/compliance")
    assert res.status_code == 200
    data = res.json()["data"]
    assert data["overall_score"] == 0.0
    assert data["frameworks"] == []


@pytest.mark.asyncio
async def test_assets_empty(client):
    res = await client.get("/api/v1/assets")
    assert res.status_code == 200
    assert res.json()["data"] == []


@pytest.mark.asyncio
async def test_attack_paths_empty(client):
    res = await client.get("/api/v1/attack-paths")
    assert res.status_code == 200


# ── Report Export ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_export_findings_csv(client):
    res = await client.get("/api/v1/reports/findings/csv")
    assert res.status_code == 200
    assert "text/csv" in res.headers["content-type"]


@pytest.mark.asyncio
async def test_export_findings_json(client):
    res = await client.get("/api/v1/reports/findings/json")
    assert res.status_code == 200
    data = res.json()
    assert "data" in data


@pytest.mark.asyncio
async def test_export_compliance_csv(client):
    res = await client.get("/api/v1/reports/compliance/csv")
    assert res.status_code == 200
    assert "text/csv" in res.headers["content-type"]


# ── Trends ────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_compliance_trend(client):
    res = await client.get("/api/v1/trends/compliance")
    assert res.status_code == 200


@pytest.mark.asyncio
async def test_finding_trend(client):
    res = await client.get("/api/v1/trends/findings")
    assert res.status_code == 200


@pytest.mark.asyncio
async def test_security_score_trend(client):
    res = await client.get("/api/v1/trends/security-score")
    assert res.status_code == 200


# ── Rule Engine Tests ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_rule_engine_initialization():
    from app.rules.engine import ALL_RULES, RuleEngine
    assert len(ALL_RULES) == 33  # 14 original + 5 RDS + 4 Lambda + 5 CT + 4 KMS + 1 (EC2-003)
    engine = RuleEngine()
    assert engine is not None


@pytest.mark.asyncio
async def test_scanner_registry():
    from app.scanners import SCANNER_REGISTRY
    assert "s3" in SCANNER_REGISTRY
    assert "iam" in SCANNER_REGISTRY
    assert "ec2" in SCANNER_REGISTRY
    assert "vpc" in SCANNER_REGISTRY
    assert "rds" in SCANNER_REGISTRY
    assert "lambda" in SCANNER_REGISTRY
    assert "cloudtrail" in SCANNER_REGISTRY
    assert "kms" in SCANNER_REGISTRY


@pytest.mark.asyncio
async def test_supported_services():
    from app.utils.constants import SUPPORTED_SERVICES
    assert len(SUPPORTED_SERVICES) == 8
    assert "s3" in SUPPORTED_SERVICES
    assert "rds" in SUPPORTED_SERVICES
    assert "lambda" in SUPPORTED_SERVICES
    assert "cloudtrail" in SUPPORTED_SERVICES
    assert "kms" in SUPPORTED_SERVICES


@pytest.mark.asyncio
async def test_compliance_frameworks():
    from app.utils.constants import ComplianceFramework
    frameworks = [f.value for f in ComplianceFramework]
    assert "CIS" in frameworks
    assert "NIST" in frameworks
    assert "PCI-DSS" in frameworks
    assert "SOC2" in frameworks
    assert "ISO-27001" in frameworks
    assert "GDPR" in frameworks


@pytest.mark.asyncio
async def test_asset_types():
    from app.utils.constants import AssetType
    types = [a.value for a in AssetType]
    assert "rds_instance" in types
    assert "lambda_function" in types
    assert "cloudtrail_trail" in types
    assert "kms_key" in types


# ── S3 Rule Evaluation ────────────────────────────────────────────────────────

def test_s3_public_access_block_rule():
    from app.rules.s3_rules import S3PublicAccessBlockRule
    rule = S3PublicAccessBlockRule()
    healthy = {"PublicAccessBlockConfiguration": {
        "BlockPublicAcls": True, "IgnorePublicAcls": True,
        "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
    }}
    assert rule.evaluate(healthy) is None
    unhealthy = {"PublicAccessBlockConfiguration": None}
    assert rule.evaluate(unhealthy) is not None


# ── KMS Rule Evaluation ───────────────────────────────────────────────────────

def test_kms_key_rotation_rule():
    from app.rules.kms_rules import KMSKeyRotationRule
    rule = KMSKeyRotationRule()
    assert rule.evaluate({"KeyRotationEnabled": False}) is not None
    assert rule.evaluate({"KeyRotationEnabled": True}) is None


# ── RDS Rule Evaluation ───────────────────────────────────────────────────────

def test_rds_encryption_rule():
    from app.rules.rds_rules import RDSEncryptionDisabledRule
    rule = RDSEncryptionDisabledRule()
    assert rule.evaluate({"StorageEncrypted": False}) is not None
    assert rule.evaluate({"StorageEncrypted": True}) is None


def test_rds_public_access_rule():
    from app.rules.rds_rules import RDSPubliclyAccessibleRule
    rule = RDSPubliclyAccessibleRule()
    assert rule.evaluate({"PubliclyAccessible": True}) is not None
    assert rule.evaluate({"PubliclyAccessible": False}) is None


def test_rds_backup_retention_rule():
    from app.rules.rds_rules import RDSBackupRetentionRule
    rule = RDSBackupRetentionRule()
    assert rule.evaluate({"BackupRetentionPeriod": 1}) is not None
    assert rule.evaluate({"BackupRetentionPeriod": 30}) is None


# ── Lambda Rule Evaluation ────────────────────────────────────────────────────

def test_lambda_deprecated_runtime_rule():
    from app.rules.lambda_rules import LambdaRuntimeDeprecatedRule
    rule = LambdaRuntimeDeprecatedRule()
    assert rule.evaluate({"Runtime": "python2.7"}) is not None
    assert rule.evaluate({"Runtime": "python3.11"}) is None


def test_lambda_timeout_rule():
    from app.rules.lambda_rules import LambdaTimeoutRule
    rule = LambdaTimeoutRule()
    assert rule.evaluate({"Timeout": 900}) is not None
    assert rule.evaluate({"Timeout": 30}) is None


# ── CloudTrail Rule Evaluation ────────────────────────────────────────────────

def test_cloudtrail_no_trails_rule():
    from app.rules.cloudtrail_rules import CloudTrailNoTrailsRule
    rule = CloudTrailNoTrailsRule()
    assert rule.evaluate({"TrailsExist": False}) is not None
    assert rule.evaluate({"TrailsExist": True}) is None


def test_cloudtrail_multi_region_rule():
    from app.rules.cloudtrail_rules import CloudTrailNotMultiRegionRule
    rule = CloudTrailNotMultiRegionRule()
    assert rule.evaluate({"IsMultiRegionTrail": False}) is not None
    assert rule.evaluate({"IsMultiRegionTrail": True}) is None


# ── Notification Service ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_notification_service_initialization():
    from app.services.notification_service import NotificationService
    svc = NotificationService()
    assert svc is not None


@pytest.mark.asyncio
async def test_slack_message_formatting():
    from app.services.notification_service import SlackChannel
    channel = SlackChannel(webhook_url="https://hooks.slack.com/test")
    findings = [
        {"severity": "critical", "rule_id": "S3-001", "title": "Test", "asset_name": "bucket", "description": "Test finding"},
    ]
    msg = channel.format_message(findings)
    assert "blocks" in msg
    assert len(msg["blocks"]) > 0


@pytest.mark.asyncio
async def test_webhook_payload_formatting():
    from app.services.notification_service import WebhookChannel
    channel = WebhookChannel(url="https://example.com/webhook")
    findings = [
        {"severity": "critical", "rule_id": "S3-001", "title": "Test", "asset_name": "bucket", "description": "Test"},
    ]
    payload = channel.format_payload(findings)
    assert payload["event"] == "security_findings"
    assert payload["critical_count"] == 1


# ── Trend Service ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_trend_service_initialization(client):
    from app.services.trend_service import TrendService
    from app.database import AsyncSessionLocal
    async with AsyncSessionLocal() as db:
        svc = TrendService(db)
        assert svc is not None


# ── Remediation Engine ────────────────────────────────────────────────────────

def test_remediation_playbook_exists():
    from app.services.remediation_service import REMEDIATION_PLAYBOOKS
    assert len(REMEDIATION_PLAYBOOKS) > 10
    assert "S3-001" in REMEDIATION_PLAYBOOKS
    assert "EC2-001" in REMEDIATION_PLAYBOOKS
    assert "IAM-001" in REMEDIATION_PLAYBOOKS
    assert "RDS-002" in REMEDIATION_PLAYBOOKS
    assert "KMS-001" in REMEDIATION_PLAYBOOKS
    assert "VPC-001" in REMEDIATION_PLAYBOOKS
    assert "CT-002" in REMEDIATION_PLAYBOOKS


@pytest.mark.asyncio
async def test_remediation_dry_run():
    from app.services.remediation_service import RemediationService
    svc = RemediationService()
    result = await svc.dry_run("S3-001", "arn:aws:s3:::test-bucket")
    assert result["dry_run"] is True
    assert result["rule_id"] == "S3-001"
    assert len(result["would_execute_steps"]) > 0


@pytest.mark.asyncio
async def test_remediation_terraform_plan():
    from app.services.remediation_service import RemediationService
    svc = RemediationService()
    result = await svc.generate_terraform_plan("S3-001", "arn:aws:s3:::test-bucket")
    assert result["rule_id"] == "S3-001"
    assert "terraform_hcl" in result


@pytest.mark.asyncio
async def test_remediation_playbooks_list():
    from app.services.remediation_service import RemediationService
    svc = RemediationService()
    playbooks = svc.get_available_playbooks(["S3-001", "EC2-001", "NONEXISTENT"])
    assert len(playbooks) == 2


# ── Cloud Security Graph ──────────────────────────────────────────────────────

def test_graph_node_creation():
    from app.services.graph_service import GraphNode
    node = GraphNode(id="test-arn", label="test-bucket", type="s3_bucket", severity="high", findings_count=2)
    assert node.id == "test-arn"
    assert node.severity == "high"
    assert node.findings_count == 2


def test_graph_edge_creation():
    from app.services.graph_service import GraphEdge
    edge = GraphEdge(source="source-arn", target="target-arn", label="uses", type="iam_trust", risk="high")
    assert edge.source == "source-arn"
    assert edge.type == "iam_trust"


def test_security_graph_to_dict():
    from app.services.graph_service import SecurityGraph, GraphNode, GraphEdge
    graph = SecurityGraph(
        nodes=[GraphNode(id="n1", label="node1", type="s3_bucket")],
        edges=[GraphEdge(source="n1", target="n2", label="connects", type="network_access")],
    )
    d = graph.to_dict()
    assert len(d["nodes"]) == 1
    assert len(d["edges"]) == 1
    assert d["stats"]["total_nodes"] == 1


# ── Executive Report Service ──────────────────────────────────────────────────

def test_score_to_grade():
    from app.services.executive_report_service import ExecutiveReportService
    svc = ExecutiveReportService.__new__(ExecutiveReportService)
    assert svc._score_to_grade(96) == "A+"
    assert svc._score_to_grade(92) == "A"
    assert svc._score_to_grade(87) == "A-"
    assert svc._score_to_grade(82) == "B+"
    assert svc._score_to_grade(72) == "B-"
    assert svc._score_to_grade(62) == "C"
    assert svc._score_to_grade(45) == "D"
    assert svc._score_to_grade(20) == "F"


def test_grade_description():
    from app.services.executive_report_service import ExecutiveReportService
    svc = ExecutiveReportService.__new__(ExecutiveReportService)
    assert "Excellent" in svc._grade_description("A+")
    assert "immediate" in svc._grade_description("F")


def test_compute_security_score():
    from app.services.executive_report_service import ExecutiveReportService
    svc = ExecutiveReportService.__new__(ExecutiveReportService)
    from app.models import Scan
    scan = Scan.__new__(Scan)
    scan.total_findings = 10
    scan.critical_count = 1
    scan.high_count = 2
    scan.medium_count = 3
    scan.low_count = 4
    score = svc._compute_security_score(scan)
    assert 0 <= score <= 100


# ── Drift Detection ───────────────────────────────────────────────────────────

def test_drift_event_dataclass():
    from app.services.drift_service import DriftEvent
    event = DriftEvent(
        event_type="compliance_drift",
        severity="high",
        title="Test Drift",
        description="Score dropped",
        timestamp="2024-01-01T00:00:00Z",
        scan_id="scan-123",
        framework="CIS",
        score_change=-10.0,
    )
    assert event.event_type == "compliance_drift"
    assert event.score_change == -10.0


# ── Multi-Cloud Scanners ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_azure_mock_scanner():
    from app.scanners.azure_scanner import AzureScanner
    scanner = AzureScanner(region="eastus", account_id="sub-123")
    results = await scanner.scan()
    assert len(results) == 3
    assert results[0].asset_type == "azure_storage_account"


@pytest.mark.asyncio
async def test_gcp_mock_scanner():
    from app.scanners.gcp_scanner import GCPScanner
    scanner = GCPScanner(region="us-central1", account_id="my-project")
    results = await scanner.scan()
    assert len(results) == 4
    assert results[0].asset_type == "gcp_storage_bucket"
