from xml.dom import minidom

from app.analyzers.topology import render_topology_svg
from app.models.device import Vendor
from app.parsers.base import get_parser


def _device(raw: str, vendor: Vendor = Vendor.CISCO_IOS):
    return get_parser(vendor).parse(raw).device


def test_renders_well_formed_svg_for_a_real_fixture() -> None:
    from pathlib import Path

    raw = (Path(__file__).parent.parent / "examples/cisco_iosxe/edge-router.cfg").read_text()
    device = _device(raw, Vendor.CISCO_IOS_XE)
    svg = render_topology_svg(device)
    assert svg.startswith("<svg")
    minidom.parseString(svg)  # raises if malformed


def test_empty_device_does_not_crash_and_still_renders_a_box() -> None:
    device = _device("hostname EMPTY\n")
    svg = render_topology_svg(device)
    minidom.parseString(svg)
    assert "EMPTY" in svg
    assert "No interfaces" in svg


def test_shows_interface_name_and_address() -> None:
    raw = "interface GigabitEthernet0/1\n ip address 10.0.0.1 255.255.255.0\n no shutdown\n"
    svg = render_topology_svg(_device(raw))
    assert "GigabitEthernet0/1" in svg
    assert "10.0.0.1/24" in svg


def test_undefined_acl_reference_is_rendered_with_the_critical_color() -> None:
    raw = "interface GigabitEthernet0/1\n ip access-group MISSING in\n"
    svg = render_topology_svg(_device(raw))
    assert "MISSING" in svg
    assert "var(--critical)" in svg


def test_defined_acl_reference_is_rendered_with_the_ok_color() -> None:
    raw = (
        "interface GigabitEthernet0/1\n ip access-group WAN-IN in\n"
        "ip access-list extended WAN-IN\n permit ip any any\n"
    )
    svg = render_topology_svg(_device(raw))
    assert "WAN-IN" in svg
    assert "var(--accent)" in svg


def test_unreachable_next_hop_is_marked_with_the_critical_color() -> None:
    raw = (
        "interface GigabitEthernet0/1\n ip address 10.0.0.1 255.255.255.0\n"
        "ip route 192.168.50.0 255.255.255.0 172.16.99.1\n"
    )
    svg = render_topology_svg(_device(raw))
    assert "172.16.99.1" in svg
    assert "ROUTING" in svg


def test_reachable_default_gateway_is_marked_ok() -> None:
    raw = "interface GigabitEthernet0/1\n ip address 10.0.0.1 255.255.255.0\n" "ip default-gateway 10.0.0.254\n"
    svg = render_topology_svg(_device(raw))
    assert "10.0.0.254" in svg


def test_shutdown_interface_is_marked_critical() -> None:
    raw = "interface GigabitEthernet0/1\n ip address 10.0.0.1 255.255.255.0\n shutdown\n"
    svg = render_topology_svg(_device(raw))
    assert "shut down" in svg


def test_mikrotik_device_renders_cleanly() -> None:
    from pathlib import Path

    raw = (Path(__file__).parent.parent / "examples/mikrotik/branch-router.rsc").read_text()
    device = _device(raw, Vendor.MIKROTIK_ROUTEROS)
    svg = render_topology_svg(device)
    minidom.parseString(svg)


def test_many_trunk_vlans_and_dual_acls_do_not_break_layout() -> None:
    raw = (
        "interface Gi0/1\n switchport mode trunk\n"
        " switchport trunk allowed vlan 1,2,3,4,5,6,7,8,9,10,11,12,13,14\n"
        " ip access-group WAN-IN in\n ip access-group WAN-OUT out\n"
    )
    svg = render_topology_svg(_device(raw))
    minidom.parseString(svg)
