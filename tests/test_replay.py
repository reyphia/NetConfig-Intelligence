from app.models.device import Vendor
from app.parsers.base import get_parser
from app.services.replay import build_replay_plan


def test_cisco_replay_uses_dotted_mask_not_cidr_suffix() -> None:
    """Regression test for the `ip address X/24` syntax bug."""
    raw = "interface Gi0/1\n ip address 10.10.10.1 255.255.255.0\n no shutdown\n"
    device = get_parser(Vendor.CISCO_IOS).parse(raw).device
    plan = build_replay_plan(device)
    commands = [step["command"] for step in plan]
    assert "ip address 10.10.10.1 255.255.255.0" in commands
    assert not any("/24" in c for c in commands)


def test_cisco_replay_orders_prerequisites_before_interfaces() -> None:
    raw = (
        "hostname R1\n"
        "enable secret 9 $9$abc\n"
        "interface Gi0/1\n ip address 10.0.0.1 255.255.255.0\n no shutdown\n"
    )
    device = get_parser(Vendor.CISCO_IOS).parse(raw).device
    plan = build_replay_plan(device)
    commands = [step["command"] for step in plan]
    hostname_idx = next(i for i, c in enumerate(commands) if c.startswith("hostname"))
    enable_idx = next(i for i, c in enumerate(commands) if c.startswith("enable secret"))
    interface_idx = next(i for i, c in enumerate(commands) if c.startswith("interface"))
    assert hostname_idx < interface_idx
    assert enable_idx < interface_idx


def test_every_step_has_required_fields() -> None:
    raw = "hostname R1\ninterface Gi0/1\n ip address 10.0.0.1 255.255.255.0\n no shutdown\n"
    device = get_parser(Vendor.CISCO_IOS).parse(raw).device
    for step in build_replay_plan(device):
        assert set(step.keys()) >= {"step", "command", "explanation", "dependencies", "risk"}
        assert step["risk"] in {"LOW", "MEDIUM", "HIGH"}


def test_high_risk_credential_steps_are_flagged() -> None:
    raw = "enable secret 9 $9$abc\n"
    device = get_parser(Vendor.CISCO_IOS).parse(raw).device
    plan = build_replay_plan(device)
    enable_step = next(s for s in plan if s["command"].startswith("enable secret"))
    assert enable_step["risk"] == "HIGH"


def test_mikrotik_replay_plan_is_vendor_specific_syntax() -> None:
    raw = "/ip address\nadd address=192.168.1.1/24 interface=ether1\n"
    device = get_parser(Vendor.MIKROTIK_ROUTEROS).parse(raw).device
    plan = build_replay_plan(device)
    commands = [step["command"] for step in plan]
    assert any(c.startswith("/ip address add") for c in commands)


def test_empty_device_yields_empty_or_trivial_plan() -> None:
    device = get_parser(Vendor.CISCO_IOS).parse("").device
    plan = build_replay_plan(device)
    assert isinstance(plan, list)
