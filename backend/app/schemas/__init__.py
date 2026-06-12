"""
CloudGuard-AI — Pydantic Schemas
Request/response validation and serialization for all API endpoints.
"""
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

from app.utils.constants import (
    AssetType,
    ComplianceFramework,
    FindingStatus,
    ScanStatus,
    Severity,
    SUPPORTED_SERVICES,
)


# ── Shared ────────────────────────────────────────────────────────────────────

class APIResponse(BaseModel):
    """Standard envelope for all API responses."""
    data: Any = None
    meta: dict = Field(default_factory=dict)
    errors: list[dict] = Field(default_factory=list)


class PaginationMeta(BaseModel):
    page: int
    limit: int
    total: int
    total_pages: int


# ── Scan Schemas ──────────────────────────────────────────────────────────────

class ScanCreateRequest(BaseModel):
    account_id: str = Field(..., min_length=12, max_length=12,
                            pattern=r"^[0-9]{12}$",
                            description="AWS 12-digit account ID (digits only)")
    region: str = Field(default="us-east-1", max_length=30,
                        pattern=r"^[a-z]{2}-[a-z]+-[0-9]$",
                        description="AWS region identifier")
    services: list[str] = Field(
        default=SUPPORTED_SERVICES,
        max_length=10,
        description="AWS services to scan",
    )
    triggered_by: str | None = Field(default=None, max_length=100,
                                     description="User or system triggering scan")

    @field_validator("services")
    @classmethod
    def validate_services(cls, v: list[str]) -> list[str]:
        allowed = set(SUPPORTED_SERVICES)
        for svc in v:
            if svc not in allowed:
                raise ValueError(f"Unsupported service: {svc}. Allowed: {allowed}")
        return v

    model_config = {"json_schema_extra": {"example": {
        "account_id": "123456789012",
        "region": "us-east-1",
        "services": ["s3", "iam", "ec2", "vpc"],
    }}}


class ScanSummary(BaseModel):
    id: str
    status: ScanStatus
    account_id: str
    region: str
    services: list[str]
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanDetail(ScanSummary):
    error_message: str | None = None
    triggered_by: str | None = None


# ── Asset Schemas ─────────────────────────────────────────────────────────────

class AssetOut(BaseModel):
    id: str
    scan_id: str
    asset_type: AssetType
    asset_id: str
    asset_name: str
    region: str
    created_at: datetime

    model_config = {"from_attributes": True}


# ── Finding Schemas ───────────────────────────────────────────────────────────

class FindingOut(BaseModel):
    id: str
    scan_id: str
    asset_id: str
    rule_id: str
    title: str
    description: str
    severity: Severity
    status: FindingStatus
    compliance_mappings: dict
    ai_explanation: str | None = None
    ai_attack_scenario: str | None = None
    ai_remediation: str | None = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class FindingWithAsset(FindingOut):
    asset: AssetOut | None = None


class SuppressFindingRequest(BaseModel):
    reason: str = Field(..., min_length=5, description="Reason for suppressing this finding")


# ── Compliance Schemas ────────────────────────────────────────────────────────

class ComplianceResultOut(BaseModel):
    id: str
    scan_id: str
    framework: ComplianceFramework
    score: float
    passed_controls: int
    failed_controls: int
    control_details: dict
    computed_at: datetime

    model_config = {"from_attributes": True}


class ComplianceSummary(BaseModel):
    """Aggregated compliance overview across all frameworks."""
    overall_score: float
    frameworks: list[ComplianceResultOut]


# ── Dashboard / Stats Schemas ─────────────────────────────────────────────────

class SeverityBreakdown(BaseModel):
    critical: int
    high: int
    medium: int
    low: int


class DashboardStats(BaseModel):
    total_findings: int
    open_findings: int
    severity_breakdown: SeverityBreakdown
    total_assets: int
    last_scan_at: datetime | None
    compliance_scores: dict[str, float]
    risk_score: float  # 0–100, computed from severity weights
