"""
CloudGuard-AI — Test Suite
Run: pytest tests/ -v

Uses an in-memory SQLite DB — no external services needed.
"""
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.database import engine, Base


@pytest_asyncio.fixture(autouse=True)
async def setup_db():
    """Create all tables before each test, drop after."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture
async def client():
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test"
    ) as c:
        yield c


# ── Health ────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_health(client):
    res = await client.get("/health")
    assert res.status_code == 200
    assert res.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_api_health(client):
    res = await client.get("/api/v1/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert "version" in data


# ── Auth ──────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_login_success(client):
    res = await client.post("/api/v1/auth/login", json={
        "username": "admin",
        "password": "cloudguard123"
    })
    assert res.status_code == 200
    data = res.json()["data"]
    assert "access_token" in data
    assert data["token_type"] == "bearer"


@pytest.mark.asyncio
async def test_login_wrong_password(client):
    res = await client.post("/api/v1/auth/login", json={
        "username": "admin",
        "password": "wrongpassword"
    })
    assert res.status_code == 401


@pytest.mark.asyncio
async def test_me_requires_auth(client):
    res = await client.get("/api/v1/auth/me")
    assert res.status_code == 401


@pytest.mark.asyncio
async def test_me_with_token(client):
    login = await client.post("/api/v1/auth/login", json={
        "username": "admin", "password": "cloudguard123"
    })
    token = login.json()["data"]["access_token"]
    res = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    assert res.json()["data"]["username"] == "admin"


# ── Scans ─────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_list_scans_empty(client):
    res = await client.get("/api/v1/scans")
    assert res.status_code == 200
    assert res.json()["data"] == []


@pytest.mark.asyncio
async def test_create_scan(client):
    res = await client.post("/api/v1/scans", json={
        "account_id": "123456789012",
        "region": "us-east-1",
        "services": ["s3", "iam"],
    })
    assert res.status_code == 202
    data = res.json()["data"]
    assert data["account_id"] == "123456789012"
    assert data["status"] == "pending"
    assert "id" in data


@pytest.mark.asyncio
async def test_get_scan_not_found(client):
    res = await client.get("/api/v1/scans/nonexistent-id")
    assert res.status_code == 404
    assert res.json()["errors"][0]["code"] == "SCAN_NOT_FOUND"


# ── Findings ──────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_list_findings_empty(client):
    res = await client.get("/api/v1/findings")
    assert res.status_code == 200
    assert res.json()["data"] == []


@pytest.mark.asyncio
async def test_dashboard_stats_empty(client):
    res = await client.get("/api/v1/dashboard/stats")
    assert res.status_code == 200
    data = res.json()["data"]
    assert data["total_findings"] == 0
    assert data["total_assets"] == 0
    assert data["risk_score"] == 0.0


# ── Compliance ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_compliance_empty(client):
    res = await client.get("/api/v1/compliance")
    assert res.status_code == 200
    data = res.json()["data"]
    assert data["overall_score"] == 0.0
    assert data["frameworks"] == []
