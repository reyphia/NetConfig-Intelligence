from app.models.device import Vendor
from app.parsers.base import get_parser
from app.rules.engine import get_rule_engine


def _fired(raw: str, vendor: Vendor) -> set[str]:
    device = get_parser(vendor).parse(raw).device
    return {f.rule_id for f in get_rule_engine().run_all(device, raw)}


# ---------- CONN-001: addressed interface administratively down ----------

def test_shutdown_interface_with_ip_is_flagged() -> None:
    raw = "interface GigabitEthernet0/1\n ip address 10.0.0.1 255.255.255.0\n shutdown\n"
    assert "CONN-001" in _fired(raw, Vendor.CISCO_IOS)


def test_shutdown_interface_without_ip_is_not_flagged_by_conn_001() -> None:
    raw = "interface GigabitEthernet0/2\n shutdown\n"
    assert "CONN-001" not in _fired(raw, Vendor.CISCO_IOS)


def test_enabled_interface_with_ip_is_not_flagged() -> None:
    raw = "interface GigabitEthernet0/1\n ip address 10.0.0.1 255.255.255.0\n no shutdown\n"
    assert "CONN-001" not in _fired(raw, Vendor.CISCO_IOS)


# ---------- CONN-002: ACL defined but never applied ----------

def test_unapplied_acl_is_flagged() -> None:
    raw = "ip access-list extended UNUSED\n permit ip any any\n"
    assert "CONN-002" in _fired(raw, Vendor.CISCO_IOS)


def test_acl_applied_to_interface_is_not_flagged() -> None:
    raw = (
        "interface GigabitEthernet0/1\n ip access-group WAN-IN in\n"
        "ip access-list extended WAN-IN\n permit ip any any\n"
    )
    assert "CONN-002" not in _fired(raw, Vendor.CISCO_IOS)


def test_acl_applied_to_vty_is_not_flagged() -> None:
    raw = "line vty 0 4\n access-class MGMT-IN in\nip access-list standard MGMT-IN\n permit 10.0.0.0 0.0.0.255\n"
    assert "CONN-002" not in _fired(raw, Vendor.CISCO_IOS)


def test_acl_used_by_nat_is_not_flagged() -> None:
    raw = (
        "access-list 1 permit 10.0.0.0 0.0.0.255\n"
        "ip nat inside source list 1 interface GigabitEthernet0/1 overload\n"
    )
    assert "CONN-002" not in _fired(raw, Vendor.CISCO_IOS)


def test_mikrotik_firewall_filter_is_never_flagged_as_dead() -> None:
    """A MikroTik chain rule is self-applying - it must never be treated as
    an unapplied ACL the way a Cisco named ACL would be."""
    raw = "/ip firewall filter\nadd action=accept chain=input protocol=icmp\n"
    assert "CONN-002" not in _fired(raw, Vendor.MIKROTIK_ROUTEROS)


# ---------- CONN-003: VLAN declared but never assigned ----------

def test_orphan_vlan_is_flagged() -> None:
    raw = "vlan 50\n name UNUSED\n"
    assert "CONN-003" in _fired(raw, Vendor.CISCO_IOS)


def test_vlan_assigned_to_an_access_port_is_not_flagged() -> None:
    raw = "vlan 50\n name USERS\ninterface GigabitEthernet0/2\n switchport access vlan 50\n"
    assert "CONN-003" not in _fired(raw, Vendor.CISCO_IOS)


def test_vlan_allowed_on_a_trunk_is_not_flagged() -> None:
    raw = (
        "vlan 50\n name USERS\n"
        "interface GigabitEthernet0/1\n switchport mode trunk\n"
        " switchport trunk allowed vlan 10,50\n"
    )
    assert "CONN-003" not in _fired(raw, Vendor.CISCO_IOS)
