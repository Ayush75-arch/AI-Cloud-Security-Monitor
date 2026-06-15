"""
pytest fixtures for CloudGuard-AI integration tests.
"""
import os

# Test env must be set before any app imports
os.environ.setdefault("TESTING", "1")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")

import pytest  # noqa: E402
from httpx import ASGITransport, AsyncClient  # noqa: E402

from app.database import Base, engine  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture(autouse=True)
async def _setup_db():
    """Create tables before each test, drop after."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.fixture
async def client():
    """HTTP client for API tests."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest.fixture
async def auth_client(client):
    """Authenticated HTTP client with JWT bearer token."""
    login = await client.post("/api/v1/auth/login", json={
        "username": "admin",
        "password": "cloudguard123",
    })
    token = login.json()["data"]["access_token"]
    client.headers["Authorization"] = f"Bearer {token}"
    return client
