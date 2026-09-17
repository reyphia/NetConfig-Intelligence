from pathlib import Path

from app.analyzers.health_score import compute_health_score
from app.models.device import Vendor
from app.parsers.base import get_parser
from app.rules.engine import get_rule_engine

ROOT = Path(__file__).parents[1]


def _findings_for(fixture: str, vendor: Vendor) -> list:
    raw = (ROOT / fixture).read_text()
    device = get_parser(vendor).parse(raw).device
    return get_rule_engine().run_all(device, raw)


def test_problematic_cisco_fixture_triggers_expected_rule_ids() -> None:
    findings = _findings_for("examples/cisco_ios/problematic-router.cfg", Vendor.CISCO_IOS)
    fired = {f.rule_id for f in findings}
    assert "CISCO-SEC-001" in fired  # telnet enabled
    assert "CISCO-SEC-002" in fired  # http without https
    assert "CISCO-SEC-004" in fired  # weak (type 7) password storage
    assert "CISCO-SEC-005" in fired  # default snmp community
    assert "CISCO-SEC-006" in fired  # permit ip any any
    assert "CISCO-BP-001" in fired  # missing banner


def test_clean_cisco_iosxe_fixture_triggers_nothing() -> None:
    findings = _findings_for("examples/cisco_iosxe/edge-router.cfg", Vendor.CISCO_IOS_XE)
    assert findings == []


def test_health_score_deducts_by_severity_weight_and_is_explainable() -> None:
    findings = _findings_for("examples/cisco_ios/problematic-router.cfg", Vendor.CISCO_IOS)
    score = compute_health_score(findings)
    assert score.total_findings == len(findings)
    assert score.overall == max(0, 100 - sum(_weight(f.severity.value) for f in findings))
    security_category = next(c for c in score.categories if c.category == "Security")
    assert security_category.finding_count == sum(1 for f in findings if f.category.value == "Security")


def test_no_findings_means_perfect_score() -> None:
    score = compute_health_score([])
    assert score.overall == 100
    assert all(c.score == 100 for c in score.categories)


def test_mikrotik_missing_input_drop_rule_is_flagged() -> None:
    raw = "/ip firewall filter\nadd action=accept chain=input connection-state=established\n"
    device = get_parser(Vendor.MIKROTIK_ROUTEROS).parse(raw).device
    findings = get_rule_engine().run_all(device, raw)
    assert any(f.rule_id == "MTK-SEC-004" for f in findings)


def test_mikrotik_default_snmp_community_is_flagged() -> None:
    raw = "/snmp community\nadd name=public\n"
    device = get_parser(Vendor.MIKROTIK_ROUTEROS).parse(raw).device
    findings = get_rule_engine().run_all(device, raw)
    assert any(f.rule_id == "MTK-SEC-007" for f in findings)


def test_mikrotik_winbox_without_source_restriction_is_flagged() -> None:
    raw = "/ip service\nset winbox disabled=no\n"
    device = get_parser(Vendor.MIKROTIK_ROUTEROS).parse(raw).device
    findings = get_rule_engine().run_all(device, raw)
    assert any(f.rule_id == "MTK-SEC-002" for f in findings)


def test_rules_are_vendor_scoped() -> None:
    """A Cisco-only rule must never fire against a MikroTik device, and vice versa."""
    raw = "/system identity\nset name=MTK\n"
    device = get_parser(Vendor.MIKROTIK_ROUTEROS).parse(raw).device
    findings = get_rule_engine().run_all(device, raw)
    assert not any(f.rule_id.startswith("CISCO-") for f in findings)


def _weight(severity: str) -> int:
    return {"INFO": 0, "LOW": 2, "MEDIUM": 5, "HIGH": 10, "CRITICAL": 20}[severity]
