from types import SimpleNamespace

import pytest

from app.services.chat_service import AIChatService


class FailingAsyncClient:
    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def post(self, *args, **kwargs):
        raise RuntimeError("All connection attempts failed")


@pytest.mark.asyncio
async def test_groq_connection_failure_uses_builtin_guidance(monkeypatch):
    import httpx

    monkeypatch.setattr(httpx, "AsyncClient", FailingAsyncClient)

    response = await AIChatService()._groq_chat(
        "How do attackers typically breach cloud environments?",
        history=[],
        current_settings=SimpleNamespace(
            GROQ_API_KEY="test-key",
            GROQ_MODEL="llama-3.3-70b-versatile",
        ),
    )

    assert "Attackers usually breach cloud environments" in response.message
    assert "Groq is currently unreachable" in response.message
    assert "Groq is configured, but the API request failed" not in response.message
