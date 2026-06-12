"""
CloudGuard-AI — Production Middleware Stack

1. RequestIDMiddleware      — X-Request-ID on every request/response
2. SecurityHeadersMiddleware — OWASP security headers
3. RequestLoggingMiddleware  — structured access log with duration
"""
import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.utils.logger import get_logger

logger = get_logger(__name__)


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Inject X-Request-ID into every request and response for tracing."""

    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request.state.request_id = request_id

        import structlog
        structlog.contextvars.bind_contextvars(request_id=request_id)

        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id

        structlog.contextvars.unbind_contextvars("request_id")
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    OWASP-recommended security headers on every response.
    Rule 11: security headers, no sensitive caching.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)

        # Prevent MIME sniffing attacks
        response.headers["X-Content-Type-Options"] = "nosniff"
        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"
        # Legacy XSS filter (IE/Edge)
        response.headers["X-XSS-Protection"] = "1; mode=block"
        # Control referrer info
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        # Disable browser features not needed
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        # Rule 11: never cache API responses
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
        response.headers["Pragma"] = "no-cache"
        # CSP — API only, no HTML served
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        # Uncomment for HTTPS/production:
        # response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"

        return response


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Structured access log — method, path, status, duration, client IP."""

    async def dispatch(self, request: Request, call_next) -> Response:
        start = time.perf_counter()
        response = await call_next(request)
        duration_ms = round((time.perf_counter() - start) * 1000, 2)

        # Skip health check noise
        if request.url.path not in ("/api/v1/health", "/health"):
            logger.info(
                "http_request",
                method=request.method,
                path=request.url.path,
                status=response.status_code,
                duration_ms=duration_ms,
                client=request.client.host if request.client else "unknown",
                request_id=getattr(request.state, "request_id", "-"),
            )

        response.headers["X-Response-Time"] = f"{duration_ms}ms"
        return response
