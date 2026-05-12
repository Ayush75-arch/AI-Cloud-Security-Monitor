"""
CloudGuard-AI — API v1 Routers
All endpoints: scans, findings, compliance, assets, IaC, attack paths, AI chat.
"""
import math
from pydantic import BaseModel as _BaseModel

from fastapi import APIRouter, Depends, Query, Request, UploadFile
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Asset, ComplianceResult, Finding, Scan
from app.schemas import (
    APIResponse,
    ComplianceSummary,
    DashboardStats,
    FindingOut,
    FindingWithAsset,
    PaginationMeta,
    ScanCreateRequest,
    ScanDetail,
    ScanSummary,
    SeverityBreakdown,
    SuppressFindingRequest,
    AssetOut,
    ComplianceResultOut,
)
from app.services.finding_service import FindingService
from app.services.scan_service import ScanService
from app.utils.constants import FindingStatus, SEVERITY_WEIGHTS, Severity
from app.config import refresh_settings, settings
from app.utils.rate_limit import limiter

router = APIRouter()


# ── Background task helper ────────────────────────────────────────────────────

async def _run_scan_background(scan_id: str) -> None:
    """Run scan pipeline directly in FastAPI event loop. No Celery needed."""
    from app.database import AsyncSessionLocal
    from app.services.scan_service import ScanService
    from app.utils.logger import get_logger
    logger = get_logger(__name__)

    async with AsyncSessionLocal() as db:
        await ScanService(db).run_scan(scan_id)

    current_settings = refresh_settings()
    if current_settings.AI_PROVIDER == "groq" and not current_settings.GROQ_API_KEY:
        logger.info("ai_skipped", reason="GROQ_API_KEY not set")
        return

    try:
        from app.database import AsyncSessionLocal
        from app.services.ai_service import AIService
        async with AsyncSessionLocal() as db:
            await AIService(db).analyze_scan_findings(scan_id)
    except Exception as exc:
        logger.warning("ai_analysis_skipped", reason=str(exc))


# ── Health ────────────────────────────────────────────────────────────────────

@router.get("/health", tags=["Health"])
async def health_check():
    current_settings = refresh_settings()
    return {
        "status": "ok",
        "version": current_settings.APP_VERSION,
        "environment": current_settings.ENVIRONMENT,
        "ai_provider": current_settings.AI_PROVIDER,
        "ai_configured": bool(current_settings.GROQ_API_KEY)
        if current_settings.AI_PROVIDER == "groq"
        else True,
    }


# ── Scans ─────────────────────────────────────────────────────────────────────

@router.post("/scans", tags=["Scans"], status_code=202)
async def create_scan(
    request: ScanCreateRequest,
    db: AsyncSession = Depends(get_db),
) -> APIResponse:
    import asyncio
    svc = ScanService(db)
    scan = await svc.create_scan(request)
    asyncio.create_task(_run_scan_background(scan.id))
    return APIResponse(
        data=ScanSummary.model_validate(scan),
        meta={"message": "Scan queued successfully"},
    )


@router.get("/scans", tags=["Scans"])
async def list_scans(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
) -> APIResponse:
    svc = ScanService(db)
    scans, total = await svc.list_scans(page=page, limit=limit)
    return APIResponse(
        data=[ScanSummary.model_validate(s) for s in scans],
        meta=PaginationMeta(
            page=page, limit=limit, total=total,
            total_pages=math.ceil(total / limit) if total else 0,
        ).model_dump(),
    )


@router.get("/scans/{scan_id}", tags=["Scans"])
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)) -> APIResponse:
    svc = ScanService(db)
    scan = await svc.get_scan(scan_id)
    return APIResponse(data=ScanDetail.model_validate(scan))


@router.get("/scans/{scan_id}/findings", tags=["Scans"])
async def get_scan_findings(
    scan_id: str,
    severity: str | None = None,
    status: str | None = None,
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
) -> APIResponse:
    svc = FindingService(db)
    findings, total = await svc.list_findings(
        scan_id=scan_id, severity=severity, status=status, page=page, limit=limit
    )
    return APIResponse(
        data=[FindingWithAsset.model_validate(f) for f in findings],
        meta=PaginationMeta(
            page=page, limit=limit, total=total,
            total_pages=math.ceil(total / limit) if total else 0,
        ).model_dump(),
    )


# ── Findings ──────────────────────────────────────────────────────────────────

@router.get("/findings", tags=["Findings"])
async def list_findings(
    severity: str | None = None,
    status: str | None = None,
    rule_id: str | None = None,
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
) -> APIResponse:
    svc = FindingService(db)
    findings, total = await svc.list_findings(
        severity=severity, status=status, rule_id=rule_id, page=page, limit=limit
    )
    return APIResponse(
        data=[FindingWithAsset.model_validate(f) for f in findings],
        meta=PaginationMeta(
            page=page, limit=limit, total=total,
            total_pages=math.ceil(total / limit) if total else 0,
        ).model_dump(),
    )


@router.get("/findings/{finding_id}", tags=["Findings"])
async def get_finding(finding_id: str, db: AsyncSession = Depends(get_db)) -> APIResponse:
    svc = FindingService(db)
    finding = await svc.get_finding(finding_id)
    return APIResponse(data=FindingWithAsset.model_validate(finding))


@router.patch("/findings/{finding_id}/suppress", tags=["Findings"])
async def suppress_finding(
    finding_id: str,
    body: SuppressFindingRequest,
    db: AsyncSession = Depends(get_db),
) -> APIResponse:
    svc = FindingService(db)
    finding = await svc.suppress_finding(finding_id, body.reason)
    return APIResponse(data=FindingOut.model_validate(finding))


# ── Compliance ────────────────────────────────────────────────────────────────

@router.get("/compliance", tags=["Compliance"])
async def get_compliance_summary(
    scan_id: str | None = None,
    db: AsyncSession = Depends(get_db),
) -> APIResponse:
    if scan_id:
        query = select(ComplianceResult).where(ComplianceResult.scan_id == scan_id)
    else:
        latest_q = await db.execute(
            select(ComplianceResult.scan_id)
            .order_by(ComplianceResult.computed_at.desc())
            .limit(1)
        )
        latest_scan_id = latest_q.scalar_one_or_none()
        if not latest_scan_id:
            return APIResponse(data=ComplianceSummary(overall_score=0.0, frameworks=[]))
        query = select(ComplianceResult).where(ComplianceResult.scan_id == latest_scan_id)

    result = await db.execute(query)
    crs = result.scalars().all()
    overall = sum(cr.score for cr in crs) / len(crs) if crs else 0.0
    return APIResponse(data=ComplianceSummary(
        overall_score=round(overall, 1),
        frameworks=[ComplianceResultOut.model_validate(cr) for cr in crs],
    ))


# ── Assets ────────────────────────────────────────────────────────────────────

@router.get("/assets", tags=["Assets"])
async def list_assets(
    scan_id: str | None = None,
    asset_type: str | None = None,
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
) -> APIResponse:
    from sqlalchemy import func as sql_func
    query = select(Asset)
    if scan_id:
        query = query.where(Asset.scan_id == scan_id)
    if asset_type:
        query = query.where(Asset.asset_type == asset_type)
    count_result = await db.execute(select(sql_func.count()).select_from(query.subquery()))
    total = count_result.scalar_one()
    offset = (page - 1) * limit
    result = await db.execute(query.offset(offset).limit(limit))
    assets = result.scalars().all()
    return APIResponse(
        data=[AssetOut.model_validate(a) for a in assets],
        meta=PaginationMeta(
            page=page, limit=limit, total=total,
            total_pages=math.ceil(total / limit) if total else 0,
        ).model_dump(),
    )


# ── Dashboard ─────────────────────────────────────────────────────────────────

@router.get("/dashboard/stats", tags=["Dashboard"])
async def get_dashboard_stats(db: AsyncSession = Depends(get_db)) -> APIResponse:
    from sqlalchemy import func as sql_func

    total_q = await db.execute(select(sql_func.count(Finding.id)))
    total_findings = total_q.scalar_one()

    open_q = await db.execute(
        select(sql_func.count(Finding.id)).where(Finding.status == FindingStatus.OPEN)
    )
    open_findings = open_q.scalar_one()

    severity_counts: dict[str, int] = {s: 0 for s in Severity}
    for sev in Severity:
        q = await db.execute(
            select(sql_func.count(Finding.id)).where(
                Finding.severity == sev, Finding.status == FindingStatus.OPEN
            )
        )
        severity_counts[sev] = q.scalar_one()

    asset_q = await db.execute(select(sql_func.count(Asset.id)))
    total_assets = asset_q.scalar_one()

    last_scan_q = await db.execute(select(Scan.completed_at).order_by(Scan.created_at.desc()).limit(1))
    last_scan_at = last_scan_q.scalar_one_or_none()

    comp_q = await db.execute(select(ComplianceResult).order_by(ComplianceResult.computed_at.desc()).limit(5))
    latest_compliance = comp_q.scalars().all()
    compliance_scores = {cr.framework: cr.score for cr in latest_compliance}

    risk_raw = (
        severity_counts[Severity.CRITICAL] * SEVERITY_WEIGHTS[Severity.CRITICAL] +
        severity_counts[Severity.HIGH] * SEVERITY_WEIGHTS[Severity.HIGH] +
        severity_counts[Severity.MEDIUM] * SEVERITY_WEIGHTS[Severity.MEDIUM] +
        severity_counts[Severity.LOW] * SEVERITY_WEIGHTS[Severity.LOW]
    )
    risk_score = min(round((risk_raw / max(total_findings, 1)) * 10, 1), 100.0)

    return APIResponse(data=DashboardStats(
        total_findings=total_findings,
        open_findings=open_findings,
        severity_breakdown=SeverityBreakdown(
            critical=severity_counts[Severity.CRITICAL],
            high=severity_counts[Severity.HIGH],
            medium=severity_counts[Severity.MEDIUM],
            low=severity_counts[Severity.LOW],
        ),
        total_assets=total_assets,
        last_scan_at=last_scan_at,
        compliance_scores=compliance_scores,
        risk_score=risk_score,
    ))


# ── IaC Scanner ───────────────────────────────────────────────────────────────

class IaCScanRequest(_BaseModel):
    content: str
    filename: str = "main.tf"


@router.post("/iac/scan", tags=["IaC"])
@limiter.limit("30/minute")
async def scan_iac(request: Request, body: IaCScanRequest) -> APIResponse:
    """Scan raw Terraform HCL for misconfigurations. No cloud creds needed."""
    from app.scanners.iac import TerraformScanner
    scanner = TerraformScanner()
    findings = scanner.scan_content(body.content, body.filename)
    return APIResponse(
        data=[{
            "rule_id": f.rule_id,
            "title": f.title,
            "description": f.description,
            "severity": f.severity,
            "file_path": f.file_path,
            "line_number": f.line_number,
            "resource_type": f.resource_type,
            "resource_name": f.resource_name,
            "compliance_mappings": f.compliance_mappings,
            "remediation": f.remediation,
        } for f in findings],
        meta={"total": len(findings), "filename": body.filename},
    )


@router.post("/iac/scan/upload", tags=["IaC"])
@limiter.limit("20/minute")
async def scan_iac_upload(request: Request, file: UploadFile) -> APIResponse:
    """Upload a .tf file for static security analysis. Validates MIME, size, and content."""
    from app.scanners.iac import TerraformScanner
    from app.utils.upload_validator import validate_terraform_upload
    from app.utils.audit_log import log_iac_scan
    client_ip = request.client.host if request.client else "unknown"
    raw = await validate_terraform_upload(file)
    content = raw.decode("utf-8", errors="ignore")
    log_iac_scan(ip=client_ip, filename=file.filename or "upload.tf")
    scanner = TerraformScanner()
    findings = scanner.scan_content(content, file.filename or "upload.tf")
    return APIResponse(
        data=[{
            "rule_id": f.rule_id,
            "title": f.title,
            "description": f.description,
            "severity": f.severity,
            "line_number": f.line_number,
            "resource_name": f.resource_name,
            "remediation": f.remediation,
            "compliance_mappings": f.compliance_mappings,
        } for f in findings],
        meta={"total": len(findings), "filename": file.filename},
    )


# ── Attack Path Analysis ──────────────────────────────────────────────────────

@router.get("/attack-paths", tags=["Attack Paths"])
async def get_attack_paths(
    scan_id: str | None = None,
    db: AsyncSession = Depends(get_db),
) -> APIResponse:
    """Identify dangerous attack chains from open findings."""
    from app.services.attack_path_service import AttackPathAnalyzer
    analyzer = AttackPathAnalyzer(db)
    paths = await analyzer.analyze(scan_id=scan_id)
    return APIResponse(
        data=[analyzer.to_dict(p) for p in paths],
        meta={"total": len(paths)},
    )


# ── AI Chat Assistant ─────────────────────────────────────────────────────────

class ChatRequest(_BaseModel):
    message: str
    history: list[dict] = []
    context: dict | None = None


@router.post("/chat", tags=["AI Chat"])
async def ai_chat(body: ChatRequest) -> APIResponse:
    """
    AI Security Copilot — natural language cloud security Q&A.
    Works without GROQ key using rule-based fallback.
    """
    from app.services.chat_service import AIChatService
    svc = AIChatService()
    response = await svc.chat(
        user_message=body.message,
        history=body.history,
        context=body.context,
    )
    return APIResponse(data={
        "message": response.message,
        "suggested_questions": response.suggested_questions,
    })
