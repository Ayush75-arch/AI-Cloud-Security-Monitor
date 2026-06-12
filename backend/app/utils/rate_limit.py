"""
CloudGuard-AI — Rate Limiter
Uses slowapi (Starlette-compatible) with in-memory storage for dev,
Redis storage for production.
"""
import asyncio
import functools

from slowapi import Limiter
from slowapi.util import get_remote_address

from app.config import settings


class _NoopLimiter:
    """Pass-through limiter used in test mode — all @limiter.limit() become no-ops."""

    enabled = False

    def limit(self, limit_value):
        def decorator(func):
            if asyncio.iscoroutinefunction(func):
                @functools.wraps(func)
                async def wrapper(*args, **kwargs):
                    return await func(*args, **kwargs)
                return wrapper
            else:
                @functools.wraps(func)
                def wrapper(*args, **kwargs):
                    return func(*args, **kwargs)
                return wrapper
        return decorator


# Use Redis backend in production, in-memory for dev/SQLite mode.
# No rate limits in test so pytest doesn't hit rate-limit errors.
if settings.ENVIRONMENT == "test":
    limiter = _NoopLimiter()  # type: ignore[assignment]
elif settings.ENVIRONMENT == "production" and settings.REDIS_URL:
    limiter = Limiter(
        key_func=get_remote_address,
        storage_uri=settings.REDIS_URL,
        default_limits=["200/minute"],
    )
else:
    limiter = Limiter(
        key_func=get_remote_address,
        default_limits=["200/minute"],
    )
