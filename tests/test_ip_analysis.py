from app.analyzers.network import analyze_networks, summarize_network
from app.models.device import Vendor
from app.parsers.base import get_parser


def test_summarize_network_computes_host_range_and_broadcast() -> None:
    summary = summarize_network("192.168.10.1", 24, "192.168.10.1", "interface test")
    assert summary is not None
    assert summary.network == "192.168.10.0"
    assert summary.first_host == "192.168.10.1"
    assert summary.last_host == "192.168.10.254"
    assert summary.broadcast == "192.168.10.255"
    assert summary.usable_hosts == 254


def test_point_to_point_slash30_has_no_broadcast_reported() -> None:
    summary = summarize_network("203.0.113.1", 30, None, "interface wan")
    assert summary is not None
    assert summary.usable_hosts == 2


def test_detects_duplicate_network_on_two_interfaces() -> None:
    raw = (
        "interface Gi0/0\n ip address 10.0.0.1 255.255.255.0\n"
        "interface Gi0/1\n ip address 10.0.0.2 255.255.255.0\n"
    )
    device = get_parser(Vendor.CISCO_IOS).parse(raw).device
    issues = analyze_networks(device).issues
    assert any(i.title.startswith("Duplicate network") for i in issues)


def test_detects_overlapping_but_not_identical_networks() -> None:
    raw = (
        "interface Gi0/0\n ip address 10.0.0.1 255.255.255.0\n"
        "interface Gi0/1\n ip address 10.0.0.200 255.255.0.0\n"
    )
    device = get_parser(Vendor.CISCO_IOS).parse(raw).device
    issues = analyze_networks(device).issues
    assert any("Overlap" in i.title for i in issues)


def test_detects_broadcast_address_configured_on_interface() -> None:
    raw = "interface Gi0/0\n ip address 10.0.0.255 255.255.255.0\n"
    device = get_parser(Vendor.CISCO_IOS).parse(raw).device
    issues = analyze_networks(device).issues
    assert any("network/broadcast" in i.title for i in issues)


def test_detects_gateway_outside_dhcp_network() -> None:
    raw = (
        "ip dhcp pool LAN\n"
        " network 10.0.10.0 255.255.255.0\n"
        " default-router 10.0.20.1\n"
    )
    device = get_parser(Vendor.CISCO_IOS).parse(raw).device
    issues = analyze_networks(device).issues
    assert any("gateway" in i.title.lower() for i in issues)


def test_detects_dhcp_range_outside_network() -> None:
    raw = (
        "/ip pool\nadd name=p0 ranges=192.168.5.10-192.168.5.20\n"
        "/ip dhcp-server\nadd address-pool=p0 interface=bridge1 name=dhcp1\n"
        "/ip dhcp-server network\nadd address=192.168.88.0/24 gateway=192.168.88.1\n"
    )
    from app.parsers.mikrotik.routeros import parse_routeros_config

    device = parse_routeros_config(raw).device
    issues = analyze_networks(device).issues
    assert any("DHCP range" in i.title for i in issues)


def test_valid_clean_config_reports_no_issues() -> None:
    raw = "interface Gi0/0\n ip address 10.0.0.1 255.255.255.0\n"
    device = get_parser(Vendor.CISCO_IOS).parse(raw).device
    assert analyze_networks(device).issues == []
