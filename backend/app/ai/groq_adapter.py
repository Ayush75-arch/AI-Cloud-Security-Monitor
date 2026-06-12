"""
CloudGuard-AI — GROQ Adapter
Uses shared GroqClient to generate security analysis for findings.
"""
import json

from app.ai.base_adapter import AIAnalysis, BaseAIAdapter
from app.ai.groq_client import groq_chat_completion
from app.config import refresh_settings
from app.utils.exceptions import AIProviderError
from app.utils.logger import get_logger

logger = get_logger(__name__)


class GROQAdapter(BaseAIAdapter):
    """Calls the GROQ Chat Completions API to generate finding analysis."""

    def __init__(self):
        current_settings = refresh_settings()
        if not current_settings.GROQ_API_KEY:
            raise AIProviderError("GROQ_API_KEY is not configured.")

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
        current_settings = refresh_settings()
        if not current_settings.GROQ_API_KEY:
            raise AIProviderError("GROQ_API_KEY is not configured.")

        payload = await groq_chat_completion(
            api_key=current_settings.GROQ_API_KEY,
            model=current_settings.GROQ_MODEL,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=600,
            temperature=0.3,
            response_format={"type": "json_object"},
        )
        return self._parse_response(payload)

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
        choices = payload.get("choices")
        if isinstance(choices, list) and choices:
            first_choice = choices[0]
            if isinstance(first_choice, dict):
                message = first_choice.get("message")
                if isinstance(message, dict):
                    content = message.get("content", "")
                    if isinstance(content, str):
                        return content
                    if isinstance(content, list):
                        return "".join(
                            item.get("text", "") for item in content if isinstance(item, dict)
                        )
        return payload.get("output_text", "") or ""

