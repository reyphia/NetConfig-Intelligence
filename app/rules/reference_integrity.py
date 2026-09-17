"""Reference-integrity checks over the normalized `Device` model.

These rules don't judge whether a configuration is *secure* - every other
rule module does that. They catch the other class of bug: a configuration
that parses cleanly and looks reasonable, but points at something (an ACL,
a VLAN, a MikroTik address-list/interface-list, an IP pool) that is never
actually declared anywhere in the file. That mismatch is invisible to a
human skimming the config - the referencing line and the missing
declaration are usually far apart - but it's exactly the class of bug
behind "I configured it, why doesn't it work?".

All checks here run against the vendor-neutral `Device` model, so a single
rule naturally covers both Cisco and MikroTik: it simply never fires on a
vendor whose parser doesn't populate the field being checked.
"""

from __future__ import annotations

from app.models.device import Device
from app.models.findings import Category, Severity
from app.rules.engine import Hit, Rule, RuleEngine

# VLAN 1 is the default/native VLAN on Cisco switches and is rarely declared
# with an explicit `vlan 1` block, so excluding it avoids near-universal
# false positives on otherwise-unremarkable configs.
_NATIVE_VLAN = 1

# RouterOS ships with these two interface lists built in; they're never
# declared with `/interface list add name=...` in an export, so they must
# be excluded from the "list was never defined" check.
_BUILTIN_INTERFACE_LISTS = {"all", "none"}


def register_all(engine: RuleEngine) -> None:
    engine.register(_interface_acl_not_defined())
    engine.register(_vty_access_class_not_defined())
    engine.register(_nat_acl_not_defined())
    engine.register(_access_vlan_not_declared())
    engine.register(_trunk_vlan_not_declared())
    engine.register(_dhcp_address_pool_not_defined())
    engine.register(_address_list_not_defined())
    engine.register(_interface_list_not_defined())


def _acl_names(device: Device) -> set[str]:
    return {acl.name for acl in device.acls}


def _interface_acl_not_defined() -> Rule:
    def check(device: Device, raw_text: str) -> list[Hit]:
        names = _acl_names(device)
        hits: list[Hit] = []
        for iface in device.interfaces:
            for direction, acl_name in (("inbound", iface.inbound_acl), ("outbound", iface.outbound_acl)):
                if acl_name and acl_name not in names:
                    hits.append(
                        Hit(
                            subject=iface.name,
                            description=(
                                f"{iface.name} applies a {direction} ACL named '{acl_name}', but no "
                                "access list with that name/number is defined anywhere in this "
                                "configuration."
                            ),
                            recommendation=(
                                f"Define access list '{acl_name}', or correct the name if it was "
                                "mistyped - a reference to a non-existent ACL either filters nothing "
                                "or blocks everything, depending on platform."
                            ),
                        )
                    )
        return hits

    return Rule(
        rule_id="REF-001",
        severity=Severity.HIGH,
        vendor=None,
        category=Category.AVAILABILITY,
        title="Interface references an undefined ACL",
        description="An interface applies an access list that is never declared in the configuration.",
        recommendation="Define the referenced access list, or correct the name if it was mistyped.",
        check=check,
    )


def _vty_access_class_not_defined() -> Rule:
    def check(device: Device, raw_text: str) -> list[Hit]:
        acl_name = device.security.vty_access_class
        if acl_name and acl_name not in _acl_names(device):
            return [
                Hit(
                    subject=acl_name,
                    description=(
                        f"VTY lines reference access-class '{acl_name}', but no access list with "
                        "that name/number is defined - remote management access is not actually "
                        "being restricted to anything."
                    ),
                )
            ]
        return []

    return Rule(
        rule_id="REF-002",
        severity=Severity.HIGH,
        vendor=None,
        category=Category.AVAILABILITY,
        title="VTY access-class references an undefined ACL",
        description="`access-class` on the VTY lines points at an access list that does not exist.",
        recommendation="Define the referenced access list with the trusted management sources, or correct the name.",
        check=check,
    )


def _nat_acl_not_defined() -> Rule:
    def check(device: Device, raw_text: str) -> list[Hit]:
        names = _acl_names(device)
        return [
            Hit(
                subject=rule.source_acl,
                description=(
                    f"A dynamic NAT rule references access list '{rule.source_acl}' via "
                    "`ip nat inside source list`, but that access list is never defined - this "
                    "NAT rule will not translate any traffic."
                ),
            )
            for rule in device.nat_rules
            if rule.source_acl and rule.source_acl not in names
        ]

    return Rule(
        rule_id="REF-003",
        severity=Severity.HIGH,
        vendor=None,
        category=Category.AVAILABILITY,
        title="NAT rule references an undefined ACL",
        description="`ip nat inside source list <acl>` points at an access list that does not exist.",
        recommendation="Define the referenced access list, or correct the name - otherwise this NAT rule is silently inactive.",
        check=check,
    )


def _access_vlan_not_declared() -> Rule:
    def check(device: Device, raw_text: str) -> list[Hit]:
        vlan_ids = {v.id for v in device.vlans}
        return [
            Hit(
                subject=iface.name,
                description=(
                    f"{iface.name} is an access port on VLAN {iface.vlan}, but VLAN {iface.vlan} "
                    "is never declared in this configuration."
                ),
            )
            for iface in device.interfaces
            if iface.vlan and iface.vlan != _NATIVE_VLAN and iface.vlan not in vlan_ids
        ]

    return Rule(
        rule_id="REF-004",
        severity=Severity.MEDIUM,
        vendor=None,
        category=Category.AVAILABILITY,
        title="Access port assigned to an undeclared VLAN",
        description="A switchport is assigned to a VLAN that is never created.",
        recommendation="Create the VLAN (`vlan <id>`), or assign the port to an existing VLAN.",
        check=check,
    )


def _trunk_vlan_not_declared() -> Rule:
    def check(device: Device, raw_text: str) -> list[Hit]:
        vlan_ids = {v.id for v in device.vlans}
        hits: list[Hit] = []
        for iface in device.interfaces:
            missing = sorted(v for v in iface.trunk_allowed_vlans if v != _NATIVE_VLAN and v not in vlan_ids)
            if missing:
                hits.append(
                    Hit(
                        subject=iface.name,
                        description=(
                            f"{iface.name} allows VLAN(s) {', '.join(str(v) for v in missing)} on its "
                            "trunk, but they are never declared in this configuration."
                        ),
                    )
                )
        return hits

    return Rule(
        rule_id="REF-005",
        severity=Severity.LOW,
        vendor=None,
        category=Category.AVAILABILITY,
        title="Trunk allows an undeclared VLAN",
        description="A trunk port's allowed-VLAN list includes a VLAN that is never created.",
        recommendation="Create the VLAN, or trim it from the trunk's allowed-VLAN list.",
        check=check,
    )


def _dhcp_address_pool_not_defined() -> Rule:
    def check(device: Device, raw_text: str) -> list[Hit]:
        pools = set(device.ip_pools)
        return [
            Hit(
                subject=pool.name,
                description=(
                    f"DHCP server '{pool.name}' references address-pool '{pool.address_pool}', but "
                    "no `/ip pool` with that name is defined - it will not hand out any leases."
                ),
            )
            for pool in device.dhcp_pools
            if pool.address_pool and pool.address_pool not in pools
        ]

    return Rule(
        rule_id="REF-006",
        severity=Severity.HIGH,
        vendor=None,
        category=Category.AVAILABILITY,
        title="DHCP server references an undefined address pool",
        description="A DHCP server's `address-pool` points at an `/ip pool` that does not exist.",
        recommendation="Define the referenced `/ip pool`, or correct the name.",
        check=check,
    )


def _address_list_not_defined() -> Rule:
    def check(device: Device, raw_text: str) -> list[Hit]:
        defined = set(device.address_lists)
        hits: list[Hit] = []
        for acl in device.acls:
            for entry in acl.entries:
                for label, list_name in (
                    ("source", entry.source_address_list),
                    ("destination", entry.destination_address_list),
                ):
                    if list_name and list_name not in defined:
                        hits.append(
                            Hit(
                                subject=list_name,
                                description=(
                                    f"A firewall rule matches on {label} address-list '{list_name}', "
                                    "but no address is ever added to a list with that name - this "
                                    "rule will never match anything."
                                ),
                            )
                        )
        for nat in device.nat_rules:
            if nat.source_address_list and nat.source_address_list not in defined:
                hits.append(
                    Hit(
                        subject=nat.source_address_list,
                        description=(
                            f"A NAT rule matches on address-list '{nat.source_address_list}', but "
                            "that address-list is never defined."
                        ),
                    )
                )
        return hits

    return Rule(
        rule_id="REF-007",
        severity=Severity.MEDIUM,
        vendor=None,
        category=Category.AVAILABILITY,
        title="Firewall/NAT rule references an undefined address-list",
        description="A rule matches on a named address-list that no `/ip firewall address-list` entry ever populates.",
        recommendation="Add the referenced address-list entries, or correct the name if it was mistyped.",
        check=check,
    )


def _interface_list_not_defined() -> Rule:
    def check(device: Device, raw_text: str) -> list[Hit]:
        defined = set(device.interface_lists) | _BUILTIN_INTERFACE_LISTS
        hits: list[Hit] = []
        for acl in device.acls:
            for entry in acl.entries:
                for label, list_name in (
                    ("in-interface-list", entry.in_interface_list),
                    ("out-interface-list", entry.out_interface_list),
                ):
                    if list_name and list_name not in defined:
                        hits.append(
                            Hit(
                                subject=list_name,
                                description=(
                                    f"A firewall rule matches on {label} '{list_name}', but no "
                                    "`/interface list` with that name is defined."
                                ),
                            )
                        )
        return hits

    return Rule(
        rule_id="REF-008",
        severity=Severity.MEDIUM,
        vendor=None,
        category=Category.AVAILABILITY,
        title="Firewall rule references an undefined interface-list",
        description="A rule matches on a named interface-list that is never declared with `/interface list`.",
        recommendation="Create the interface list (`/interface list add name=...`) with its members, or correct the name.",
        check=check,
    )
