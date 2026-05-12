"""
CloudGuard-AI — GROQ Adapter
Uses GROQ Responses API to generate security analysis for findings.
"""
import json

import httpx

from app.ai.base_adapter import AIAnalysis, BaseAIAdapter
from app.config import settings
from app.utils.exceptions import AIProviderError
from app.utils.logger import get_logger

logger = get_logger(__name__)


class GROQAdapter(BaseAIAdapter):
    """Calls the GROQ Responses API to generate finding analysis."""

    def __init__(self):
        if not settings.GROQ_API_KEY:
            raise AIProviderError("GROQ_API_KEY is not configured.")
        self._endpoint = "https://api.groq.com/openai/v1/responses"
        self._headers = {
            "Authorization": f"Bearer {settings.GROQ_API_KEY}",
            "Content-Type": "application/json",
        }

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
            async with httpx.AsyncClient(timeout=60.0, headers=self._headers) as client:
                response = await client.post(
                    self._endpoint,
                    json={
                        "model": settings.GROQ_MODEL,
                        "input": prompt,
                        "max_output_tokens": 600,
                        "temperature": 0.3,
                    },
                )
                response.raise_for_status()
                return self._parse_response(response.json())

        except httpx.HTTPStatusError as exc:
            logger.error("groq_api_error", error=str(exc), rule_id=rule_id)
            raise AIProviderError("GROQ API returned an error.") from exc
        except Exception as exc:
            logger.error("groq_api_error", error=str(exc), rule_id=rule_id)
            raise AIProviderError(str(exc)) from exc

    @staticmethod
    def _parse_response(payload: dict) -> AIAnalysis:
        raw = GROQAdapter._extract_text(payload)
        try:
            data = json.loads(raw)
            return AIAnalysis(
                explanation=data.get("explanation", "Analysis unavailable."),
                attack_scenario=data.get("attack_scenario", "Attack scenario unavailable."),
                remediation=data.get("remediation", "Remediation steps unavailable."),
            )
        except json.JSONDecodeError:
            logger.error("groq_json_parse_failed", raw=raw[:200])
            return AIAnalysis(
                explanation="AI analysis could not be parsed.",
                attack_scenario="N/A",
                remediation="Please review AWS security best practices.",
            )

    @staticmethod
    def _extract_text(payload: dict) -> str:
        if isinstance(payload.get("output"), str):
            return payload["output"]

        output = payload.get("output")
        if isinstance(output, list) and output:
            first = output[0]
            if isinstance(first, dict):
                if "output_text" in first:
                    return first["output_text"]
                if "content" in first and isinstance(first["content"], list):
                    return "".join(
                        item.get("text", "") for item in first["content"] if isinstance(item, dict)
                    )
        return payload.get("output_text", "") or ""
