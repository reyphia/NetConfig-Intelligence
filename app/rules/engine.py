from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from app.models.device import Device, Vendor
from app.models.findings import Category, Finding, Severity


@dataclass
class Hit:
    """One occurrence of a rule firing. `description`/`recommendation` override
    the rule's defaults only when the specific occurrence needs more detail
    (e.g. naming the exact interface or SNMP community involved)."""

    subject: str | None = None
    description: str | None = None
    recommendation: str | None = None


# A check receives the parsed Device and the original raw text (some checks,
# like "telnet enabled", are easier to confirm from raw text) and returns
# zero or more hits. It never needs to know its own rule_id/severity/etc -
# Rule.run() fills those in, so checks can't drift from their own metadata.
CheckFn = Callable[[Device, str], list[Hit]]


@dataclass
class Rule:
    rule_id: str
    severity: Severity
    vendor: Vendor | None  # None = applies to all vendors
    category: Category
    title: str
    description: str
    recommendation: str
    check: CheckFn = field(repr=False)

    def run(self, device: Device, raw_text: str) -> list[Finding]:
        if self.vendor is not None and device.vendor != self.vendor:
            return []
        hits = self.check(device, raw_text)
        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                vendor=self.vendor.value if self.vendor else "all",
                category=self.category,
                title=self.title,
                description=hit.description or self.description,
                recommendation=hit.recommendation or self.recommendation,
                subject=hit.subject,
            )
            for hit in hits
        ]


class RuleEngine:
    def __init__(self) -> None:
        self._rules: list[Rule] = []

    def register(self, rule: Rule) -> None:
        self._rules.append(rule)

    def run_all(self, device: Device, raw_text: str) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self._rules:
            findings.extend(rule.run(device, raw_text))
        return findings

    @property
    def rules(self) -> list[Rule]:
        return list(self._rules)


_engine: RuleEngine | None = None


def get_rule_engine() -> RuleEngine:
    global _engine
    if _engine is None:
        _engine = RuleEngine()
        from app.rules import cisco_rules, connectivity, mikrotik_rules, reference_integrity

        cisco_rules.register_all(_engine)
        mikrotik_rules.register_all(_engine)
        reference_integrity.register_all(_engine)
        connectivity.register_all(_engine)
    return _engine
