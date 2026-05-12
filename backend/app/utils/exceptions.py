"""
CloudGuard-AI — Custom Exceptions & Handlers

Rule 5: Never expose internal error details to users.
- External responses: generic messages only
- Internal logs: full exception details with request context
"""
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.utils.logger import get_logger

logger = get_logger(__name__)


# ── Domain Exceptions ─────────────────────────────────────────────────────────

class CloudGuardError(Exception):
    def __init__(self, message: str, code: str = "INTERNAL_ERROR"):
        self.message = message
        self.code = code
        super().__init__(message)


class ScanNotFoundError(CloudGuardError):
    def __init__(self, scan_id: str):
        super().__init__(f"Scan {scan_id} not found", "SCAN_NOT_FOUND")


class FindingNotFoundError(CloudGuardError):
    def __init__(self, finding_id: str):
        super().__init__(f"Finding {finding_id} not found", "FINDING_NOT_FOUND")


class ScanAlreadyRunningError(CloudGuardError):
    def __init__(self):
        super().__init__("A scan is already running for this account", "SCAN_ALREADY_RUNNING")


class AWSCredentialsError(CloudGuardError):
    def __init__(self, detail: str = ""):
        super().__init__(f"Invalid or missing AWS credentials. {detail}".strip(), "AWS_CREDENTIALS_ERROR")


class AIProviderError(CloudGuardError):
    def __init__(self, detail: str = ""):
        super().__init__(f"AI provider error: {detail}", "AI_PROVIDER_ERROR")


# ── Response helpers ──────────────────────────────────────────────────────────

def _error_response(status: int, code: str, message: str) -> JSONResponse:
    """Generic envelope for error responses — never includes stack traces."""
    return JSONResponse(
        status_code=status,
        content={"data": None, "errors": [{"code": code, "message": message}]},
    )


# ── FastAPI Exception Handlers ────────────────────────────────────────────────

def register_exception_handlers(app: FastAPI) -> None:

    @app.exception_handler(ScanNotFoundError)
    async def scan_not_found(_: Request, exc: ScanNotFoundError):
        return _error_response(404, exc.code, exc.message)

    @app.exception_handler(FindingNotFoundError)
    async def finding_not_found(_: Request, exc: FindingNotFoundError):
        return _error_response(404, exc.code, exc.message)

    @app.exception_handler(ScanAlreadyRunningError)
    async def scan_already_running(_: Request, exc: ScanAlreadyRunningError):
        return _error_response(409, exc.code, exc.message)

    @app.exception_handler(AWSCredentialsError)
    async def aws_credentials(_: Request, exc: AWSCredentialsError):
        # Rule 5: don't expose internal AWS error details to user
        return _error_response(400, exc.code, "Invalid or missing AWS credentials")

    @app.exception_handler(AIProviderError)
    async def ai_provider(_: Request, exc: AIProviderError):
        return _error_response(502, exc.code, "AI analysis service unavailable")

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception):
        # Rule 5: log full details internally, return generic message externally
        logger.error(
            "unhandled_exception",
            path=request.url.path,
            method=request.method,
            error_type=type(exc).__name__,
            # Full exception logged here — never sent to client
            error_detail=str(exc),
        )
        return _error_response(500, "INTERNAL_ERROR", "An unexpected error occurred")
