import os

os.environ["ENVIRONMENT"] = "test"

import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.database import engine, Base


@pytest_asyncio.fixture(autouse=True)
async def setup_db():
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


async def _get_token(client) -> str:
    res = await client.post("/api/v1/auth/login", json={
        "username": "admin", "password": "cloudguard123"
    })
    return res.json()["data"]["access_token"]


@pytest_asyncio.fixture
async def auth_client(client):
    token = await _get_token(client)
    client.headers["Authorization"] = f"Bearer {token}"
    return client
