from pathlib import Path

from app.models.device import InterfaceMode, SecretType, Vendor
from app.parsers.base import detect_vendor, get_parser
from app.parsers.cisco.common import _parse_ace_line

ROOT = Path(__file__).parents[1]


def test_branch_router_fixture_parses_core_fields() -> None:
    raw = (ROOT / "examples/cisco_ios/branch-router.cfg").read_text()
    device = get_parser(Vendor.CISCO_IOS).parse(raw).device
    assert device.hostname == "BRANCH-RTR"
    assert device.security.service_password_encryption is True
    lan = device.get_interface("GigabitEthernet0/0")
    assert lan is not None
    assert lan.ipv4[0].address == "10.10.10.1"
    assert lan.ipv4[0].prefix_length == 24
    assert device.routing.static_routes[0].next_hop == "203.0.113.1"


def test_vendor_detection_prefers_iosxe_when_markers_present() -> None:
    raw = (ROOT / "examples/cisco_iosxe/edge-router.cfg").read_text()
    result = detect_vendor(raw)
    assert result.vendor == Vendor.CISCO_IOS_XE
    assert result.confidence > 0.5


def test_vendor_detection_falls_back_to_ios_without_iosxe_markers() -> None:
    raw = (ROOT / "examples/cisco_ios/branch-router.cfg").read_text()
    result = detect_vendor(raw)
    assert result.vendor == Vendor.CISCO_IOS


def test_repeated_interface_block_merges_instead_of_duplicating() -> None:
    """Real `show running-config` never repeats an `interface X` header, but
    hand-edited fragments sometimes do - the parser must merge, not create a
    ghost duplicate with no IP/description that would look "unused"."""
    raw = (
        "interface GigabitEthernet0/1\n"
        " description WAN\n"
        " ip address 203.0.113.1 255.255.255.252\n"
        " no shutdown\n"
        "interface GigabitEthernet0/1\n"
        " ip access-group WAN-IN in\n"
    )
    device = get_parser(Vendor.CISCO_IOS).parse(raw).device
    matching = [i for i in device.interfaces if i.name == "GigabitEthernet0/1"]
    assert len(matching) == 1
    assert matching[0].description == "WAN"
    assert matching[0].inbound_acl == "WAN-IN"
    assert matching[0].enabled is True


def test_malformed_block_does_not_crash_the_parser() -> None:
    raw = "hostname OK\ninterface GigabitEthernet0/0\n ip address not-an-ip totally-invalid\n"
    result = get_parser(Vendor.CISCO_IOS).parse(raw)
    assert result.device.hostname == "OK"  # rest of the config still parses


def test_ace_address_parsing_handles_any_host_and_network_forms() -> None:
    any_any = _parse_ace_line("permit ip any any", 10)
    assert any_any.source == "any"
    assert any_any.destination == "any"

    host_form = _parse_ace_line("permit tcp host 10.1.1.1 any eq 22", 10)
    assert host_form.source == "host 10.1.1.1"
    assert host_form.destination == "any"

    network_form = _parse_ace_line("deny ip 10.0.0.0 0.0.0.255 192.168.1.0 0.0.0.255", 10)
    assert network_form.source == "10.0.0.0 0.0.0.255"
    assert network_form.destination == "192.168.1.0 0.0.0.255"


def test_type7_and_type9_secrets_are_classified_correctly() -> None:
    raw = (
        "username plain7 password 7 0822455D0A16\n"
        "enable secret 9 $9$abc$def\n"
    )
    device = get_parser(Vendor.CISCO_IOS).parse(raw).device
    plain7_user = next(u for u in device.users if u.username == "plain7")
    assert plain7_user.secret_type == SecretType.CISCO_TYPE7
    assert device.security.enable_secret is not None
    assert device.security.enable_secret.secret_type == SecretType.CISCO_TYPE9


def test_vty_access_class_round_trips_through_the_model() -> None:
    raw = "line vty 0 4\n transport input ssh\n access-class MGMT-IN in\n"
    device = get_parser(Vendor.CISCO_IOS).parse(raw).device
    assert device.security.vty_access_class == "MGMT-IN"


def test_trunk_and_access_switchports() -> None:
    raw = (
        "interface GigabitEthernet0/1\n switchport mode trunk\n"
        " switchport trunk allowed vlan 10,20,30\n"
        "interface GigabitEthernet0/2\n switchport access vlan 10\n"
    )
    device = get_parser(Vendor.CISCO_IOS).parse(raw).device
    trunk = device.get_interface("GigabitEthernet0/1")
    access = device.get_interface("GigabitEthernet0/2")
    assert trunk is not None and trunk.mode == InterfaceMode.TRUNK
    assert trunk.trunk_allowed_vlans == [10, 20, 30]
    assert access is not None and access.mode == InterfaceMode.ACCESS
    assert access.vlan == 10
