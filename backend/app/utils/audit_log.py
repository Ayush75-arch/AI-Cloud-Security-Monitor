"""
CloudGuard-AI — Audit Logger
Structured security event logging for:
- Authentication events (login success/failure, token use)
- Authorization failures (forbidden access attempts)
- Suspicious activity (rate limit hits, invalid tokens)
- Privilege escalation attempts
- Scan triggers (who ran what)
- Finding suppressions (who suppressed what)

In production: ship these logs to SIEM (Splunk, Datadog, CloudWatch).
"""
from enum import Enum
from typing import Any

from app.utils.logger import get_logger

audit = get_logger("cloudguard.audit")


class AuditEvent(str, Enum):
    # Auth
    LOGIN_SUCCESS         = "auth.login.success"
    LOGIN_FAILURE         = "auth.login.failure"
    LOGIN_BLOCKED         = "auth.login.blocked"        # rate limited
    TOKEN_INVALID         = "auth.token.invalid"
    TOKEN_EXPIRED         = "auth.token.expired"
    # Authorization
    ACCESS_DENIED         = "authz.access.denied"
    PRIVILEGE_ATTEMPT     = "authz.privilege.escalation_attempt"
    # Scan
    SCAN_TRIGGERED        = "scan.triggered"
    SCAN_COMPLETED        = "scan.completed"
    SCAN_FAILED           = "scan.failed"
    # Findings
    FINDING_SUPPRESSED    = "finding.suppressed"
    FINDING_RESOLVED      = "finding.resolved"
    # IaC
    IAC_SCAN_TRIGGERED    = "iac.scan.triggered"
    # Suspicious
    RATE_LIMIT_HIT        = "security.rate_limit"
    INVALID_INPUT         = "security.invalid_input"
    UPLOAD_REJECTED       = "security.upload.rejected"


def log_event(
    event: AuditEvent,
    username: str | None = None,
    ip: str | None = None,
    detail: str | None = None,
    **extra: Any,
) -> None:
    """Emit a structured audit log entry."""
    audit.info(
        event.value,
        audit_event=event.value,
        username=username or "anonymous",
        ip=ip or "unknown",
        detail=detail or "",
        **extra,
    )


def log_login_success(username: str, ip: str) -> None:
    log_event(AuditEvent.LOGIN_SUCCESS, username=username, ip=ip)


def log_login_failure(username: str, ip: str) -> None:
    log_event(AuditEvent.LOGIN_FAILURE, username=username, ip=ip,
              detail="Invalid credentials")


def log_login_blocked(username: str, ip: str) -> None:
    log_event(AuditEvent.LOGIN_BLOCKED, username=username, ip=ip,
              detail="Rate limit exceeded on login endpoint")


def log_token_invalid(ip: str, reason: str = "") -> None:
    log_event(AuditEvent.TOKEN_INVALID, ip=ip, detail=reason)


def log_access_denied(username: str, ip: str, resource: str) -> None:
    log_event(AuditEvent.ACCESS_DENIED, username=username, ip=ip,
              detail=f"Attempted to access: {resource}")


def log_scan_triggered(username: str, account_id: str, region: str, scan_id: str) -> None:
    log_event(AuditEvent.SCAN_TRIGGERED, username=username,
              account_id=account_id, region=region, scan_id=scan_id)


def log_finding_suppressed(username: str, finding_id: str, reason: str) -> None:
    log_event(AuditEvent.FINDING_SUPPRESSED, username=username,
              finding_id=finding_id, detail=reason)


def log_upload_rejected(ip: str, filename: str, reason: str) -> None:
    log_event(AuditEvent.UPLOAD_REJECTED, ip=ip,
              detail=f"File '{filename}' rejected: {reason}")


def log_iac_scan(ip: str, filename: str) -> None:
    log_event(AuditEvent.IAC_SCAN_TRIGGERED, ip=ip, detail=filename)
