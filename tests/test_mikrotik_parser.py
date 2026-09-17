from pathlib import Path

from app.models.device import Vendor
from app.parsers.base import detect_vendor, get_parser

ROOT = Path(__file__).parents[1]


def test_branch_router_fixture_parses_core_fields() -> None:
    raw = (ROOT / "examples/mikrotik/branch-router.rsc").read_text()
    device = get_parser(Vendor.MIKROTIK_ROUTEROS).parse(raw).device
    assert device.hostname == "BRANCH-MT"
    ether2 = device.get_interface("ether2")
    assert ether2 is not None
    assert ether2.ipv4[0].address == "10.20.20.1"
    assert ether2.ipv4[0].prefix_length == 24
    ssh = next(m for m in device.management if m.name == "ssh")
    assert ssh.enabled is True
    assert ssh.allowed_sources == ["10.20.20.0/24"]
    telnet = next(m for m in device.management if m.name == "telnet")
    assert telnet.enabled is False


def test_vendor_detection_recognises_routeros_export() -> None:
    raw = (ROOT / "examples/mikrotik/branch-router.rsc").read_text()
    result = detect_vendor(raw)
    assert result.vendor == Vendor.MIKROTIK_ROUTEROS
    assert result.confidence > 0.5


def test_ppp_secret_is_captured_as_plaintext_credential() -> None:
    raw = "/ppp secret\nadd name=vpnuser password=SuperSecret123 service=any\n"
    device = get_parser(Vendor.MIKROTIK_ROUTEROS).parse(raw).device
    secret = next(u for u in device.users if u.username == "vpnuser")
    assert secret.secret_raw == "SuperSecret123"
    assert secret.group == "ppp"


def test_firewall_filter_rules_are_modeled() -> None:
    raw = (
        "/ip firewall filter\n"
        "add action=accept chain=input connection-state=established,related\n"
        "add action=drop chain=input src-address=0.0.0.0/0\n"
    )
    device = get_parser(Vendor.MIKROTIK_ROUTEROS).parse(raw).device
    acl = next(a for a in device.acls if a.kind == "firewall_filter")
    assert acl.entries[0].action == "permit"
    assert acl.entries[1].action == "deny"


def test_dhcp_pool_links_range_and_network_by_address() -> None:
    raw = (
        "/ip pool\n"
        "add name=dhcp_pool0 ranges=192.168.88.10-192.168.88.254\n"
        "/ip dhcp-server\n"
        "add address-pool=dhcp_pool0 interface=bridge1 name=dhcp1\n"
        "/ip dhcp-server network\n"
        "add address=192.168.88.0/24 dns-server=192.168.88.1 gateway=192.168.88.1\n"
    )
    device = get_parser(Vendor.MIKROTIK_ROUTEROS).parse(raw).device
    pool = device.dhcp_pools[0]
    assert pool.range_start == "192.168.88.10"
    assert pool.network == "192.168.88.0"
    assert pool.gateway == "192.168.88.1"


def test_service_disabled_selector_is_parsed_even_with_find_bracket() -> None:
    raw = "/ip service\nset [ find default=yes ] disabled=yes\nset ssh disabled=no\n"
    # The `[ find default=yes ]` selector has no service name; the parser
    # should not crash, and the explicit `ssh` line should still be modeled.
    device = get_parser(Vendor.MIKROTIK_ROUTEROS).parse(raw).device
    ssh = next(m for m in device.management if m.name == "ssh")
    assert ssh.enabled is True


def test_malformed_line_does_not_crash_the_parser() -> None:
    raw = "/ip address\nadd address=not-an-ip interface=ether1\n"
    result = get_parser(Vendor.MIKROTIK_ROUTEROS).parse(raw)
    # Should not raise; either produces a warning or leaves it unparsed.
    assert result.device is not None
