"""
CloudGuard-AI — API v1 Routers
All endpoints: scans, findings, compliance, assets, IaC, attack paths, AI chat.
"""
import asyncio
import json
import math
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, Query, Request, UploadFile
from fastapi.responses import PlainTextResponse, StreamingResponse
from pydantic import BaseModel as _BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import TokenData, get_current_user
from app.config import refresh_settings
from app.database import get_db
from app.models import Asset, ComplianceResult, Finding, Scan
from app.schemas import (
    APIResponse,
    AssetOut,
    ComplianceResultOut,
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
)
from app.services.finding_service import FindingService
from app.services.scan_service import ScanService
from app.utils.constants import FindingStatus, SEVERITY_WEIGHTS, Severity
from app.utils.rate_limit import limiter

router = APIRouter()

# Convenience alias for auth dependency
AuthUser = Annotated[TokenData, Depends(get_current_user)]


# ── Background task helper ────────────────────────────────────────────────────

async def _run_scan_background(scan_id: str) -> None:
    """Delegates to ScanService.run_scan_with_ai — all logic lives in the service layer."""
    from app.database import AsyncSessionLocal
    async with AsyncSessionLocal() as db:
        await ScanService(db).run_scan_with_ai(scan_id)


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
    background_tasks: BackgroundTasks,
    _: AuthUser,
    db: AsyncSession = Depends(get_db),
) -> APIResponse:
    svc = ScanService(db)
    scan = await svc.create_scan(request)
    background_tasks.add_task(_run_scan_background, scan.id)
    return APIResponse(
        data=ScanSummary.model_validate(scan),
        meta={"message": "Scan queued successfully"},
    )


@router.get("/scans", tags=["Scans"])
async def list_scans(
    _: AuthUser,
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
async def get_scan(scan_id: str, _: AuthUser, db: AsyncSession = Depends(get_db)) -> APIResponse:
    svc = ScanService(db)
    scan = await svc.get_scan(scan_id)
    return APIResponse(data=ScanDetail.model_validate(scan))


@router.get("/scans/{scan_id}/findings", tags=["Scans"])
async def get_scan_findings(
    scan_id: str,
    _: AuthUser,
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
    _: AuthUser,
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
async def get_finding(finding_id: str, _: AuthUser, db: AsyncSession = Depends(get_db)) -> APIResponse:
    svc = FindingService(db)
    finding = await svc.get_finding(finding_id)
    return APIResponse(data=FindingWithAsset.model_validate(finding))


@router.patch("/findings/{finding_id}/suppress", tags=["Findings"])
async def suppress_finding(
    finding_id: str,
    body: SuppressFindingRequest,
    _: AuthUser,
    db: AsyncSession = Depends(get_db),
) -> APIResponse:
    svc = FindingService(db)
    finding = await svc.suppress_finding(finding_id, body.reason)
    return APIResponse(data=FindingOut.model_validate(finding))


# ── Compliance ────────────────────────────────────────────────────────────────

@router.get("/compliance", tags=["Compliance"])
async def get_compliance_summary(
    _: AuthUser,
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
    _: AuthUser,
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
async def get_dashboard_stats(_: AuthUser, db: AsyncSession = Depends(get_db)) -> APIResponse:
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
async def scan_iac(request: Request, body: IaCScanRequest, _: AuthUser) -> APIResponse:
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
async def scan_iac_upload(request: Request, file: UploadFile, _: AuthUser) -> APIResponse:
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
    _: AuthUser,
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
async def ai_chat(_: AuthUser, body: ChatRequest) -> APIResponse:
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


# ── Scan Status SSE Stream ────────────────────────────────────────────────────


@router.get("/scans/{scan_id}/stream", tags=["Scans"])
async def stream_scan_status(
    scan_id: str,
    _: AuthUser,
    db: AsyncSession = Depends(get_db),
) -> StreamingResponse:
    """
    SSE stream for real-time scan status updates.
    Polls scan every 1s, emits status events, closes when scan completes/fails.
    """

    async def event_generator():
        from app.database import AsyncSessionLocal
        terminal_states = {"completed", "failed"}
        while True:
            async with AsyncSessionLocal() as session:
                result = await session.execute(select(Scan).where(Scan.id == scan_id))
                scan = result.scalar_one_or_none()
                if not scan:
                    yield f"event: error\ndata: {json.dumps({'error': 'Scan not found'})}\n\n"
                    return
                payload = {
                    "status": scan.status,
                    "total_findings": scan.total_findings,
                    "critical_count": scan.critical_count,
                    "high_count": scan.high_count,
                    "medium_count": scan.medium_count,
                    "low_count": scan.low_count,
                    "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                    "error_message": scan.error_message,
                }
                yield f"data: {json.dumps(payload)}\n\n"
                if scan.status in terminal_states:
                    return
            await asyncio.sleep(1.5)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ── Report Export ─────────────────────────────────────────────────────────────


@router.get("/reports/findings/csv", tags=["Reports"])
async def export_findings_csv(
    _: AuthUser,
    scan_id: str | None = None,
    db: AsyncSession = Depends(get_db),
) -> PlainTextResponse:
    from app.services.report_service import ReportService
    csv_content = await ReportService(db).export_findings_csv(scan_id=scan_id)
    return PlainTextResponse(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=findings_{scan_id or 'all'}.csv"},
    )


@router.get("/reports/findings/json", tags=["Reports"])
async def export_findings_json(
    _: AuthUser,
    scan_id: str | None = None,
    db: AsyncSession = Depends(get_db),
) -> APIResponse:
    from app.services.report_service import ReportService
    json_content = await ReportService(db).export_findings_json(scan_id=scan_id)
    return APIResponse(data=json.loads(json_content), meta={"format": "json"})


@router.get("/reports/compliance/csv", tags=["Reports"])
async def export_compliance_csv(
    _: AuthUser,
    scan_id: str | None = None,
    db: AsyncSession = Depends(get_db),
) -> PlainTextResponse:
    from app.services.report_service import ReportService
    csv_content = await ReportService(db).export_compliance_csv(scan_id=scan_id)
    return PlainTextResponse(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=compliance_{scan_id or 'all'}.csv"},
    )


@router.get("/reports/scan/{scan_id}/full", tags=["Reports"])
async def export_full_report(
    scan_id: str,
    _: AuthUser,
    db: AsyncSession = Depends(get_db),
) -> PlainTextResponse:
    from app.services.report_service import ReportService
    report = await ReportService(db).export_full_report_json(scan_id=scan_id)
    return PlainTextResponse(
        content=report,
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=scan_report_{scan_id}.json"},
    )


# ── Security Trends ───────────────────────────────────────────────────────────

@router.get("/trends/compliance", tags=["Trends"])
async def compliance_trend(
    _: AuthUser,
    framework: str | None = None,
    limit: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
) -> APIResponse:
    from app.services.trend_service import TrendService
    data = await TrendService(db).get_compliance_trend(framework=framework, limit=limit)
    return APIResponse(data=data, meta={"count": len(data)})


@router.get("/trends/findings", tags=["Trends"])
async def finding_trend(
    _: AuthUser,
    limit: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
) -> APIResponse:
    from app.services.trend_service import TrendService
    data = await TrendService(db).get_finding_trend(limit=limit)
    return APIResponse(data=data, meta={"count": len(data)})


@router.get("/trends/security-score", tags=["Trends"])
async def security_score_trend(
    _: AuthUser,
    limit: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
) -> APIResponse:
    from app.services.trend_service import TrendService
    data = await TrendService(db).get_security_score_trend(limit=limit)
    return APIResponse(data=data, meta={"count": len(data)})


# ── Notifications ─────────────────────────────────────────────────────────────

class NotificationTestRequest(_BaseModel):
    channel: str = "slack"  # slack, webhook, email


@router.post("/notifications/test", tags=["Notifications"])
async def test_notification(
    body: NotificationTestRequest,
    _: AuthUser,
) -> APIResponse:
    from app.services.notification_service import NotificationService
    test_findings = [
        {
            "rule_id": "TEST-001",
            "title": "Test Alert - No Action Required",
            "severity": "low",
            "asset_name": "test-bucket",
            "description": "This is a test notification from CloudGuard-AI.",
        }
    ]
    svc = NotificationService()
    sent = await svc.send_alert(test_findings)
    return APIResponse(data={"channels_available": len(svc._channels), "sent": sent})


@router.post("/notifications/send", tags=["Notifications"])
async def send_notifications(
    _: AuthUser,
    severity_threshold: str = "high",
    db: AsyncSession = Depends(get_db),
) -> APIResponse:
    from app.services.notification_service import NotificationService
    from app.models import Finding
    from app.utils.constants import FindingStatus

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    threshold = sev_order.get(severity_threshold, 1)

    result = await db.execute(
        select(Finding).where(
            Finding.status == FindingStatus.OPEN,
        ).order_by(Finding.created_at.desc()).limit(50)
    )
    findings = result.scalars().all()

    filtered = [
        {
            "id": f.id,
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "asset_name": f.asset.asset_name if f.asset else "unknown",
            "description": f.description,
        }
        for f in findings
        if sev_order.get(f.severity, 99) <= threshold
    ]

    if not filtered:
        return APIResponse(data={"sent": 0, "message": "No findings matching threshold."})

    svc = NotificationService()
    sent = await svc.send_alert(filtered)
    return APIResponse(data={"sent": sent, "total_matching": len(filtered)})


# ── Auto-Remediation Engine ───────────────────────────────────────────────────

class RemediationRequest(_BaseModel):
    rule_id: str
    asset_arn: str
    approved: bool = False


@router.get("/remediation/playbooks", tags=["Remediation"])
async def list_playbooks(
    _: AuthUser,
    rule_ids: str | None = None,
) -> APIResponse:
    from app.services.remediation_service import RemediationService
    svc = RemediationService()
    ids = rule_ids.split(",") if rule_ids else []
    if ids:
        playbooks = svc.get_available_playbooks(ids)
    else:
        from app.services.remediation_service import REMEDIATION_PLAYBOOKS
        playbooks = [
            {
                "rule_id": p.rule_id,
                "title": p.title,
                "description": p.description,
                "risk_level": p.risk_level,
                "requires_approval": p.requires_approval,
                "steps_count": len(p.steps),
            }
            for p in REMEDIATION_PLAYBOOKS.values()
        ]
    return APIResponse(data=playbooks, meta={"total": len(playbooks)})


@router.post("/remediation/dry-run", tags=["Remediation"])
async def dry_run_remediation(
    body: RemediationRequest,
    _: AuthUser,
) -> APIResponse:
    from app.services.remediation_service import RemediationService
    svc = RemediationService()
    result = await svc.dry_run(body.rule_id, body.asset_arn)
    return APIResponse(data=result)


@router.post("/remediation/execute", tags=["Remediation"])
async def execute_remediation(
    body: RemediationRequest,
    _: AuthUser,
) -> APIResponse:
    from app.services.remediation_service import RemediationService
    svc = RemediationService()
    result = await svc.execute_remediation(body.rule_id, body.asset_arn, body.approved)
    return APIResponse(data=result)


@router.post("/remediation/terraform-plan", tags=["Remediation"])
async def generate_terraform_plan(
    body: RemediationRequest,
    _: AuthUser,
) -> APIResponse:
    from app.services.remediation_service import RemediationService
    svc = RemediationService()
    result = await svc.generate_terraform_plan(body.rule_id, body.asset_arn)
    return APIResponse(data=result)


# ── Cloud Security Graph ──────────────────────────────────────────────────────

@router.get("/graph", tags=["Security Graph"])
async def get_security_graph(
    _: AuthUser,
    scan_id: str | None = None,
    db: AsyncSession = Depends(get_db),
) -> APIResponse:
    from app.services.graph_service import GraphBuilder
    builder = GraphBuilder(db)
    graph = await builder.build(scan_id=scan_id)
    return APIResponse(data=graph.to_dict())


@router.get("/graph/attack-paths", tags=["Security Graph"])
async def get_graph_attack_paths(
    _: AuthUser,
    scan_id: str | None = None,
    db: AsyncSession = Depends(get_db),
) -> APIResponse:
    from app.services.graph_service import GraphBuilder
    builder = GraphBuilder(db)
    paths = await builder.get_attack_paths_graph(scan_id=scan_id)
    return APIResponse(data=paths, meta={"count": len(paths)})


@router.get("/graph/hotspots", tags=["Security Graph"])
async def get_hotspot_nodes(
    _: AuthUser,
    top_n: int = Query(10, ge=1, le=50),
    scan_id: str | None = None,
    db: AsyncSession = Depends(get_db),
) -> APIResponse:
    from app.services.graph_service import GraphBuilder
    builder = GraphBuilder(db)
    await builder.build(scan_id=scan_id)
    hotspots = builder.get_hotspot_nodes(top_n=top_n)
    return APIResponse(data=hotspots, meta={"count": len(hotspots)})


# ── Executive Reports ─────────────────────────────────────────────────────────

@router.get("/reports/executive/json", tags=["Reports"])
async def executive_report_json(
    _: AuthUser,
    scan_id: str | None = None,
    db: AsyncSession = Depends(get_db),
) -> APIResponse:
    from app.services.executive_report_service import ExecutiveReportService
    report = await ExecutiveReportService(db).generate_json_report(scan_id=scan_id)
    return APIResponse(data=report)


@router.get("/reports/executive/html", tags=["Reports"])
async def executive_report_html(
    _: AuthUser,
    scan_id: str | None = None,
    db: AsyncSession = Depends(get_db),
) -> PlainTextResponse:
    from app.services.executive_report_service import ExecutiveReportService
    html = await ExecutiveReportService(db).generate_html_report(scan_id=scan_id)
    return PlainTextResponse(
        content=html,
        media_type="text/html",
        headers={"Content-Disposition": f"inline; filename=executive_report_{scan_id or 'latest'}.html"},
    )


# ── Compliance Drift ──────────────────────────────────────────────────────────

@router.get("/drift", tags=["Drift Detection"])
async def detect_drift(
    _: AuthUser,
    db: AsyncSession = Depends(get_db),
) -> APIResponse:
    from app.services.drift_service import DriftDetector
    detector = DriftDetector(db)
    events = await detector.detect()
    return APIResponse(data=events, meta={"count": len(events) if isinstance(events, list) else 1})
