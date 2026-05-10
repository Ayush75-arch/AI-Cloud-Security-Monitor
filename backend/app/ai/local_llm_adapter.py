"""
CloudGuard-AI — Local LLM Adapter
Uses Ollama REST API for air-gapped / local deployments.
Model: llama3, mistral, or any Ollama-compatible model.
"""
import json

import httpx

from app.ai.base_adapter import AIAnalysis, BaseAIAdapter
from app.config import settings
from app.utils.exceptions import AIProviderError
from app.utils.logger import get_logger

logger = get_logger(__name__)


class LocalLLMAdapter(BaseAIAdapter):
    """Calls Ollama /api/generate endpoint for local inference."""

    def __init__(self):
        self._base_url = settings.LOCAL_LLM_BASE_URL
        self._model = settings.LOCAL_LLM_MODEL

    async def analyze_finding(
        self,
        rule_id: str,
        title: str,
        description: str,
        severity: str,
        asset_type: str,
        asset_name: str,
    ) -> AIAnalysis:
        prompt = self._build_prompt(rule_id, title, description, severity, asset_type, asset_name)

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(
                    f"{self._base_url}/api/generate",
                    json={
                        "model": self._model,
                        "prompt": prompt,
                        "stream": False,
                        "format": "json",
                    },
                )
                response.raise_for_status()
                data = response.json()
                raw = data.get("response", "{}")
                return self._parse_response(raw)

        except httpx.ConnectError as exc:
            logger.error("ollama_connect_failed", url=self._base_url)
            raise AIProviderError(f"Cannot connect to Ollama at {self._base_url}") from exc
        except httpx.HTTPStatusError as exc:
            raise AIProviderError(f"Ollama HTTP error: {exc.response.status_code}") from exc

    @staticmethod
    def _parse_response(raw: str) -> AIAnalysis:
        try:
            # Strip markdown fences if model adds them
            clean = raw.strip().removeprefix("```json").removesuffix("```").strip()
            data = json.loads(clean)
            return AIAnalysis(
                explanation=data.get("explanation", "Analysis unavailable."),
                attack_scenario=data.get("attack_scenario", "N/A"),
                remediation=data.get("remediation", "Review AWS security documentation."),
            )
        except json.JSONDecodeError:
            logger.warning("local_llm_json_parse_failed", raw=raw[:200])
            return AIAnalysis(
                explanation=raw[:500] if raw else "Analysis unavailable.",
                attack_scenario="N/A",
                remediation="Review AWS security documentation.",
            )
