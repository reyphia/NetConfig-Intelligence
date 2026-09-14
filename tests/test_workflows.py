from pathlib import Path

from app.analyzers.network import analyze_networks
from app.models.device import Vendor
from app.parsers.base import detect_vendor, get_parser
from app.services import analyze, render_device, update_interface
from app.services.diff import configuration_diff
from app.services.replay import build_replay_plan
from app.services.validation import validate_device

ROOT = Path(__file__).parents[1]


def test_cisco_fixture_parses_and_renders() -> None:
    raw = (ROOT / "examples/cisco_ios/branch-router.cfg").read_text()
    parsed = get_parser(Vendor.CISCO_IOS).parse(raw).device
    assert parsed.hostname == "BRANCH-RTR"
    assert len(parsed.interfaces) == 2
    assert "hostname BRANCH-RTR" in render_device(parsed)


def test_mikrotik_fixture_detects_and_parses() -> None:
    raw = (ROOT / "examples/mikrotik/branch-router.rsc").read_text()
    assert detect_vendor(raw).vendor == Vendor.MIKROTIK_ROUTEROS
    parsed = get_parser(Vendor.MIKROTIK_ROUTEROS).parse(raw).device
    assert parsed.hostname == "BRANCH-MT"
    assert len(parsed.interfaces) >= 2


def test_editor_validation_diff_and_replay_are_model_based() -> None:
    raw = "hostname EDGE\ninterface GigabitEthernet0/1\n ip address 10.0.0.1 255.255.255.0\n no shutdown\n"
    session = analyze(raw, "cisco_ios")
    update_interface(session, "GigabitEthernet0/1", "10.20.30.1", 24)
    rendered = session.rendered_text or ""
    assert "10.20.30.1" in rendered
    assert configuration_diff(session.sanitization.sanitized_text, rendered)["changed_lines"] > 0
    assert build_replay_plan(session.device)
    assert not any(check["status"] == "blocking" for check in validate_device(session.device))


def test_network_analysis_detects_overlapping_interfaces() -> None:
    raw = "interface Gi0/0\n ip address 10.0.0.1 255.255.255.0\ninterface Gi0/1\n ip address 10.0.0.2 255.255.255.0\n"
    device = get_parser(Vendor.CISCO_IOS).parse(raw).device
    assert any(issue.title.startswith("Duplicate network") for issue in analyze_networks(device).issues)
