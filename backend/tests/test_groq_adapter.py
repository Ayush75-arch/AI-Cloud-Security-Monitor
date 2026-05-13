from types import SimpleNamespace

import httpx
import pytest

from app.ai.base_adapter import AIAnalysis
from app.ai.groq_adapter import GROQAdapter


class FakeGroqResponse:
    def raise_for_status(self):
        pass

    def json(self):
        return {
            "choices": [
                {
                    "message": {
                        "content": (
                            '{"explanation":"explain","attack_scenario":"attack",'
                            '"remediation":"remediate"}'
                        )
                    }
                }
            ]
        }


class RecordingAsyncClient:
    init_kwargs = None
    post_args = None

    def __init__(self, *args, **kwargs):
        RecordingAsyncClient.init_kwargs = kwargs

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def post(self, endpoint, json):
        RecordingAsyncClient.post_args = {"endpoint": endpoint, "json": json}
        return FakeGroqResponse()


@pytest.mark.asyncio
async def test_groq_adapter_uses_chat_completions_payload(monkeypatch):
    monkeypatch.setattr(httpx, "AsyncClient", RecordingAsyncClient)
    monkeypatch.setattr(
        "app.ai.groq_adapter.refresh_settings",
        lambda: SimpleNamespace(
            GROQ_API_KEY="test-key",
            GROQ_MODEL="llama-3.3-70b-versatile",
        ),
    )

    analysis = await GROQAdapter().analyze_finding(
        rule_id="S3-001",
        title="Public S3 Bucket",
        description="Bucket allows public read access.",
        severity="critical",
        asset_type="s3",
        asset_name="demo-bucket",
    )

    assert analysis == AIAnalysis(
        explanation="explain",
        attack_scenario="attack",
        remediation="remediate",
    )
    assert RecordingAsyncClient.init_kwargs["headers"]["Authorization"] == "Bearer test-key"

    request = RecordingAsyncClient.post_args
    assert request["endpoint"] == "https://api.groq.com/openai/v1/chat/completions"
    assert request["json"]["model"] == "llama-3.3-70b-versatile"
    assert request["json"]["max_tokens"] == 600
    assert request["json"]["temperature"] == 0.3
    assert request["json"]["response_format"] == {"type": "json_object"}
    assert "input" not in request["json"]
    assert request["json"]["messages"][0]["role"] == "user"
    assert "S3-001" in request["json"]["messages"][0]["content"]
