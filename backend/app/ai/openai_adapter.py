"""
CloudGuard-AI — OpenAI Adapter
Uses GPT-4o to generate security analysis for findings.
Includes retry logic and JSON parsing with fallback.
"""
import json

import openai

from app.ai.base_adapter import AIAnalysis, BaseAIAdapter
from app.config import settings
from app.utils.exceptions import AIProviderError
from app.utils.logger import get_logger

logger = get_logger(__name__)


class OpenAIAdapter(BaseAIAdapter):
    """Calls OpenAI Chat Completions API to generate finding analysis."""

    def __init__(self):
        if not settings.OPENAI_API_KEY:
            raise AIProviderError("OPENAI_API_KEY is not configured.")
        self._client = openai.AsyncOpenAI(api_key=settings.OPENAI_API_KEY)

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
            response = await self._client.chat.completions.create(
                model=settings.OPENAI_MODEL,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=600,
                temperature=0.3,   # Low temp = consistent, factual output
                response_format={"type": "json_object"},
            )
            raw = response.choices[0].message.content or "{}"
            return self._parse_response(raw)

        except openai.RateLimitError as exc:
            logger.warning("openai_rate_limit", rule_id=rule_id)
            raise AIProviderError("OpenAI rate limit reached.") from exc
        except openai.APIError as exc:
            logger.error("openai_api_error", error=str(exc), rule_id=rule_id)
            raise AIProviderError(str(exc)) from exc

    @staticmethod
    def _parse_response(raw: str) -> AIAnalysis:
        try:
            data = json.loads(raw)
            return AIAnalysis(
                explanation=data.get("explanation", "Analysis unavailable."),
                attack_scenario=data.get("attack_scenario", "Attack scenario unavailable."),
                remediation=data.get("remediation", "Remediation steps unavailable."),
            )
        except json.JSONDecodeError:
            logger.error("openai_json_parse_failed", raw=raw[:200])
            return AIAnalysis(
                explanation="AI analysis could not be parsed.",
                attack_scenario="N/A",
                remediation="Please review AWS security best practices.",
            )
