"""
CloudGuard-AI — AI Base Adapter
Abstract interface for AI providers. Swap OpenAI ↔ local LLM via config.
"""
import abc
from dataclasses import dataclass

from app.utils.constants import Severity


@dataclass
class AIAnalysis:
    explanation: str
    attack_scenario: str
    remediation: str


class BaseAIAdapter(abc.ABC):
    """
    Pluggable AI adapter interface.
    Implementations: OpenAIAdapter, LocalLLMAdapter.
    """

    @abc.abstractmethod
    async def analyze_finding(
        self,
        rule_id: str,
        title: str,
        description: str,
        severity: str,
        asset_type: str,
        asset_name: str,
    ) -> AIAnalysis:
        """Generate AI explanation, attack scenario, and remediation for a finding."""
        ...

    def _build_prompt(
        self,
        rule_id: str,
        title: str,
        description: str,
        severity: str,
        asset_type: str,
        asset_name: str,
    ) -> str:
        return f"""You are a senior cloud security engineer analyzing AWS misconfiguration findings.

Finding Details:
- Rule ID: {rule_id}
- Title: {title}
- Asset Type: {asset_type}
- Asset Name: {asset_name}
- Severity: {severity.upper()}
- Description: {description}

Respond ONLY with a valid JSON object with exactly these three keys:
{{
  "explanation": "Why this finding is dangerous (2-3 sentences, technical but clear)",
  "attack_scenario": "A realistic attack scenario exploiting this misconfiguration (2-3 sentences)",
  "remediation": "Specific, actionable remediation steps (3-5 numbered steps)"
}}

Do not include markdown, code fences, or any text outside the JSON object."""
