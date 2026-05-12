"""
CloudGuard-AI — Rate Limiter
Uses slowapi (Starlette-compatible) with in-memory storage for dev,
Redis storage for production.
"""
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.config import settings

# Use Redis backend in production, in-memory for dev/SQLite mode
if settings.ENVIRONMENT == "production" and settings.REDIS_URL:
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
