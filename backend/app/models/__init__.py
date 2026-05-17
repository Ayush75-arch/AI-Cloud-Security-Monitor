"""
CloudGuard-AI — ORM Models
SQLAlchemy 2.0 declarative models for all core entities.
"""
import uuid
from datetime import datetime

from sqlalchemy import (
    JSON,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.utils.constants import (
    AssetType,
    FindingStatus,
    ScanStatus,
    Severity,
)


def _uuid() -> str:
    return str(uuid.uuid4())


# ── Scan ──────────────────────────────────────────────────────────────────────

class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    status: Mapped[str] = mapped_column(String(20), default=ScanStatus.PENDING, index=True)
    account_id: Mapped[str] = mapped_column(String(12), index=True)
    region: Mapped[str] = mapped_column(String(30))
    services: Mapped[list] = mapped_column(JSON, default=list)
    triggered_by: Mapped[str | None] = mapped_column(String(100), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    total_findings: Mapped[int] = mapped_column(Integer, default=0)
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, default=0)
    low_count: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    assets: Mapped[list["Asset"]] = relationship("Asset", back_populates="scan", lazy="select")
    findings: Mapped[list["Finding"]] = relationship("Finding", back_populates="scan", lazy="select")
    compliance_results: Mapped[list["ComplianceResult"]] = relationship(
        "ComplianceResult", back_populates="scan", lazy="select"
    )


# ── Asset ─────────────────────────────────────────────────────────────────────

class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    asset_type: Mapped[str] = mapped_column(String(30), index=True)
    asset_id: Mapped[str] = mapped_column(String(255))   # ARN or resource ID
    asset_name: Mapped[str] = mapped_column(String(255))
    region: Mapped[str] = mapped_column(String(30))
    raw_config: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    scan: Mapped["Scan"] = relationship("Scan", back_populates="assets")
    findings: Mapped[list["Finding"]] = relationship("Finding", back_populates="asset", lazy="select")


# ── Finding ───────────────────────────────────────────────────────────────────

class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    rule_id: Mapped[str] = mapped_column(String(20), index=True)  # e.g. "S3-001"
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(10), index=True)
    status: Mapped[str] = mapped_column(String(20), default=FindingStatus.OPEN, index=True)
    compliance_mappings: Mapped[dict] = mapped_column(JSON, default=dict)
    # AI-generated fields (populated async after scan)
    ai_explanation: Mapped[str | None] = mapped_column(Text, nullable=True)
    ai_attack_scenario: Mapped[str | None] = mapped_column(Text, nullable=True)
    ai_remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    suppressed_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    fingerprint: Mapped[str | None] = mapped_column(String(16), nullable=True, index=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    scan: Mapped["Scan"] = relationship("Scan", back_populates="findings")
    asset: Mapped["Asset"] = relationship("Asset", back_populates="findings")


# ── Compliance Result ─────────────────────────────────────────────────────────

class ComplianceResult(Base):
    __tablename__ = "compliance_results"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    framework: Mapped[str] = mapped_column(String(20))   # CIS / NIST / PCI-DSS
    score: Mapped[float] = mapped_column(Float)           # 0.0–100.0
    passed_controls: Mapped[int] = mapped_column(Integer, default=0)
    failed_controls: Mapped[int] = mapped_column(Integer, default=0)
    control_details: Mapped[dict] = mapped_column(JSON, default=dict)
    computed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    scan: Mapped["Scan"] = relationship("Scan", back_populates="compliance_results")
