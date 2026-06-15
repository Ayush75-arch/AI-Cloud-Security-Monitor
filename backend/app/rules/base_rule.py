"""
CloudGuard-AI — Base Rule
All detection rules inherit from BaseRule.
Rules are stateless: evaluate() takes an asset config and returns a Finding or None.
"""
import abc
from dataclasses import dataclass, field
from typing import Any

from app.utils.constants import Severity


@dataclass
class RuleFinding:
    """Raw finding produced by a rule before DB persistence."""
    rule_id: str
    title: str
    description: str
    severity: Severity
    compliance_mappings: dict = field(default_factory=dict)


class BaseRule(abc.ABC):
    """
    Abstract detection rule.

    Each rule encapsulates:
    - A unique rule_id (e.g. "S3-001")
    - Human-readable title + description template
    - Severity classification
    - Compliance framework control mappings
    - evaluate() logic against raw asset config
    """

    rule_id: str = ""
    title: str = ""
    description: str = ""
    severity: Severity = Severity.MEDIUM
    compliance_mappings: dict | None = None   # {CIS: "x.y", NIST: "AC-x", PCI_DSS: "y.z"}
    applicable_asset_types: list[str] | None = None

    def __init__(self) -> None:
        if self.compliance_mappings is None:
            self.compliance_mappings = {}
        if self.applicable_asset_types is None:
            self.applicable_asset_types = []

    @abc.abstractmethod
    def evaluate(self, asset_config: dict[str, Any]) -> RuleFinding | None:
        """
        Evaluate asset config against this rule.

        Returns RuleFinding if misconfiguration detected, None if asset is compliant.
        """
        ...

    def _finding(self, description_override: str | None = None) -> RuleFinding:
        """Helper to create a RuleFinding from rule metadata."""
        return RuleFinding(
            rule_id=self.rule_id,
            title=self.title,
            description=description_override or self.description,
            severity=self.severity,
            compliance_mappings=self.compliance_mappings or {},
        )

    def __repr__(self) -> str:
        return f"<Rule {self.rule_id}: {self.title}>"
