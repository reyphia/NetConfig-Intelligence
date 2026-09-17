from app.models.device import Vendor
from app.parsers.base import get_parser
from app.renderers.cisco import CiscoIOSRenderer, CiscoIOSXERenderer
from app.renderers.cisco_common import prefix_to_mask
from app.renderers.mikrotik import MikroTikRouterOSRenderer


def test_prefix_to_mask_common_values() -> None:
    assert prefix_to_mask(24) == "255.255.255.0"
    assert prefix_to_mask(30) == "255.255.255.252"
    assert prefix_to_mask(16) == "255.255.0.0"
    assert prefix_to_mask(8) == "255.0.0.0"


def test_cisco_renderer_uses_dotted_mask_not_cidr_suffix() -> None:
    raw = "hostname R1\ninterface GigabitEthernet0/1\n ip address 10.10.10.1 255.255.255.0\n no shutdown\n"
    device = get_parser(Vendor.CISCO_IOS).parse(raw).device
    rendered = CiscoIOSRenderer().render(device)
    assert "ip address 10.10.10.1 255.255.255.0" in rendered
    assert "/24" not in rendered


def test_cisco_iosxe_renderer_preserves_vty_access_class() -> None:
    raw = "line vty 0 4\n transport input ssh\n access-class MGMT-IN in\n"
    device = get_parser(Vendor.CISCO_IOS_XE).parse(raw).device
    rendered = CiscoIOSXERenderer().render(device)
    assert "access-class MGMT-IN in" in rendered


def test_cisco_renderer_round_trip_preserves_interface_state() -> None:
    raw = (
        "hostname R1\n"
        "interface GigabitEthernet0/1\n"
        " description Uplink\n"
        " ip address 10.10.10.1 255.255.255.0\n"
        " no shutdown\n"
        "interface GigabitEthernet0/2\n"
        " shutdown\n"
    )
    device = get_parser(Vendor.CISCO_IOS).parse(raw).device
    rendered = CiscoIOSRenderer().render(device)
    reparsed = get_parser(Vendor.CISCO_IOS).parse(rendered).device
    gi1 = reparsed.get_interface("GigabitEthernet0/1")
    gi2 = reparsed.get_interface("GigabitEthernet0/2")
    assert gi1 is not None and gi1.enabled and gi1.ipv4[0].address == "10.10.10.1"
    assert gi2 is not None and not gi2.enabled


def test_mikrotik_renderer_emits_address_and_route() -> None:
    raw = (
        "/ip address\nadd address=192.168.1.1/24 interface=ether1\n"
        "/ip route\nadd dst-address=0.0.0.0/0 gateway=192.168.1.254\n"
    )
    device = get_parser(Vendor.MIKROTIK_ROUTEROS).parse(raw).device
    rendered = MikroTikRouterOSRenderer().render(device)
    assert "add address=192.168.1.1/24 interface=ether1" in rendered
    assert "gateway=192.168.1.254" in rendered


def test_renderer_compatibility_warning_names_target_platform() -> None:
    assert "Cisco IOS" in CiscoIOSRenderer().compatibility_warning()
    assert "MikroTik RouterOS" in MikroTikRouterOSRenderer().compatibility_warning()
