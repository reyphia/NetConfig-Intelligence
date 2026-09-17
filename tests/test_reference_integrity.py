from app.models.device import Vendor
from app.parsers.base import get_parser
from app.rules.engine import get_rule_engine


def _findings(raw: str, vendor: Vendor) -> list:
    device = get_parser(vendor).parse(raw).device
    return get_rule_engine().run_all(device, raw)


def _fired(raw: str, vendor: Vendor) -> set[str]:
    return {f.rule_id for f in _findings(raw, vendor)}


# ---------- REF-001: interface ACL not defined ----------

def test_interface_acl_reference_missing_is_flagged() -> None:
    raw = "interface GigabitEthernet0/1\n ip access-group WAN-IN in\n"
    assert "REF-001" in _fired(raw, Vendor.CISCO_IOS)


def test_interface_acl_reference_that_exists_is_not_flagged() -> None:
    raw = (
        "interface GigabitEthernet0/1\n ip access-group WAN-IN in\n"
        "ip access-list extended WAN-IN\n permit ip any any\n"
    )
    assert "REF-001" not in _fired(raw, Vendor.CISCO_IOS)


# ---------- REF-002: vty access-class not defined ----------

def test_vty_access_class_missing_is_flagged() -> None:
    raw = "line vty 0 4\n access-class MGMT-IN in\n"
    assert "REF-002" in _fired(raw, Vendor.CISCO_IOS)


def test_vty_access_class_that_exists_is_not_flagged() -> None:
    raw = "line vty 0 4\n access-class MGMT-IN in\naccess-list 10 permit 10.0.0.0 0.0.0.255\n"
    # named differently on purpose - still missing
    assert "REF-002" in _fired(raw, Vendor.CISCO_IOS)
    raw_ok = "line vty 0 4\n access-class MGMT-IN in\nip access-list standard MGMT-IN\n permit 10.0.0.0 0.0.0.255\n"
    assert "REF-002" not in _fired(raw_ok, Vendor.CISCO_IOS)


# ---------- REF-003: NAT ACL not defined ----------

def test_nat_acl_reference_missing_is_flagged() -> None:
    raw = "ip nat inside source list 1 interface GigabitEthernet0/1 overload\n"
    assert "REF-003" in _fired(raw, Vendor.CISCO_IOS)


def test_nat_acl_reference_that_exists_is_not_flagged() -> None:
    raw = (
        "access-list 1 permit 10.0.0.0 0.0.0.255\n"
        "ip nat inside source list 1 interface GigabitEthernet0/1 overload\n"
    )
    assert "REF-003" not in _fired(raw, Vendor.CISCO_IOS)


# ---------- REF-004 / REF-005: VLAN not declared ----------

def test_access_vlan_not_declared_is_flagged() -> None:
    raw = "interface GigabitEthernet0/2\n switchport access vlan 30\n"
    assert "REF-004" in _fired(raw, Vendor.CISCO_IOS)


def test_access_vlan_1_is_never_flagged() -> None:
    """VLAN 1 is the default VLAN and normally has no explicit `vlan 1` block."""
    raw = "interface GigabitEthernet0/2\n switchport access vlan 1\n"
    assert "REF-004" not in _fired(raw, Vendor.CISCO_IOS)


def test_access_vlan_that_is_declared_is_not_flagged() -> None:
    raw = "vlan 30\n name USERS\ninterface GigabitEthernet0/2\n switchport access vlan 30\n"
    assert "REF-004" not in _fired(raw, Vendor.CISCO_IOS)


def test_trunk_allowed_vlan_not_declared_is_flagged() -> None:
    raw = (
        "vlan 10\n name USERS\n"
        "interface GigabitEthernet0/1\n switchport mode trunk\n"
        " switchport trunk allowed vlan 10,20\n"
    )
    findings = _findings(raw, Vendor.CISCO_IOS)
    assert any(f.rule_id == "REF-005" and "20" in f.description for f in findings)


# ---------- REF-006: DHCP address-pool not defined (MikroTik) ----------

def test_dhcp_address_pool_missing_is_flagged() -> None:
    raw = "/ip dhcp-server\nadd address-pool=dhcp_pool0 interface=bridge1 name=dhcp1\n"
    assert "REF-006" in _fired(raw, Vendor.MIKROTIK_ROUTEROS)


def test_dhcp_address_pool_that_exists_is_not_flagged() -> None:
    raw = (
        "/ip pool\nadd name=dhcp_pool0 ranges=192.168.88.10-192.168.88.254\n"
        "/ip dhcp-server\nadd address-pool=dhcp_pool0 interface=bridge1 name=dhcp1\n"
    )
    assert "REF-006" not in _fired(raw, Vendor.MIKROTIK_ROUTEROS)


# ---------- REF-007: address-list not defined (MikroTik) ----------

def test_firewall_address_list_missing_is_flagged() -> None:
    raw = "/ip firewall filter\nadd action=drop chain=input src-address-list=BLOCKED\n"
    assert "REF-007" in _fired(raw, Vendor.MIKROTIK_ROUTEROS)


def test_firewall_address_list_that_exists_is_not_flagged() -> None:
    raw = (
        "/ip firewall address-list\nadd list=BLOCKED address=203.0.113.0/24\n"
        "/ip firewall filter\nadd action=drop chain=input src-address-list=BLOCKED\n"
    )
    assert "REF-007" not in _fired(raw, Vendor.MIKROTIK_ROUTEROS)


def test_nat_address_list_missing_is_flagged() -> None:
    raw = "/ip firewall nat\nadd action=masquerade chain=srcnat src-address-list=LAN-HOSTS\n"
    assert "REF-007" in _fired(raw, Vendor.MIKROTIK_ROUTEROS)


# ---------- REF-008: interface-list not defined (MikroTik) ----------

def test_firewall_interface_list_missing_is_flagged() -> None:
    raw = "/ip firewall filter\nadd action=drop chain=forward in-interface-list=WAN\n"
    assert "REF-008" in _fired(raw, Vendor.MIKROTIK_ROUTEROS)


def test_firewall_interface_list_that_exists_is_not_flagged() -> None:
    raw = (
        "/interface list\nadd name=WAN\n"
        "/ip firewall filter\nadd action=drop chain=forward in-interface-list=WAN\n"
    )
    assert "REF-008" not in _fired(raw, Vendor.MIKROTIK_ROUTEROS)


def test_builtin_interface_lists_are_never_flagged() -> None:
    raw = "/ip firewall filter\nadd action=accept chain=forward in-interface-list=all\n"
    assert "REF-008" not in _fired(raw, Vendor.MIKROTIK_ROUTEROS)


# ---------- rules are additive, not accidentally cross-vendor ----------

def test_reference_rules_are_vendor_neutral_but_only_fire_where_populated() -> None:
    """A MikroTik config with no ACL/VLAN references shouldn't trip the
    Cisco-flavoured checks (REF-001..005), and vice versa."""
    raw = "/system identity\nset name=MTK\n"
    assert _fired(raw, Vendor.MIKROTIK_ROUTEROS).isdisjoint({"REF-001", "REF-002", "REF-003", "REF-004", "REF-005"})
