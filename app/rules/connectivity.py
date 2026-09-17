"""Connectivity/availability checks that are neither "reference integrity"
(app.rules.reference_integrity - things that point at something undefined)
nor cross-subnet arithmetic (app.analyzers.network - IP/route consistency).

This module covers the third, more mundane class of "configured it, but it
doesn't actually do anything" bug: the thing itself is defined correctly,
but it's disabled, or nothing in the configuration ever uses it.
"""

from __future__ import annotations

from app.models.device import Device, Interface
from app.models.findings import Category, Severity
from app.rules.engine import Hit, Rule, RuleEngine


def register_all(engine: RuleEngine) -> None:
    engine.register(_shutdown_interface_with_ip())
    engine.register(_dead_acl())
    engine.register(_orphan_vlan())


def _describe_addresses(iface: Interface) -> str:
    return ", ".join(f"{a.address}/{a.prefix_length}" for a in iface.ipv4)


def _shutdown_interface_with_ip() -> Rule:
    def check(device: Device, raw_text: str) -> list[Hit]:
        return [
            Hit(
                subject=iface.name,
                description=(
                    f"{iface.name} has {_describe_addresses(iface)} configured but is "
                    "administratively shut down - it will not pass any traffic until it is "
                    "brought back up."
                ),
            )
            for iface in device.interfaces
            if not iface.enabled and iface.ipv4
        ]

    return Rule(
        rule_id="CONN-001",
        severity=Severity.MEDIUM,
        vendor=None,
        category=Category.AVAILABILITY,
        title="Addressed interface is administratively down",
        description="An interface has an IP address configured but is shut down.",
        recommendation="Run `no shutdown` (Cisco) if this interface should be active, or remove the unused address.",
        check=check,
    )


def _dead_acl() -> Rule:
    def check(device: Device, raw_text: str) -> list[Hit]:
        used: set[str] = set()
        for iface in device.interfaces:
            if iface.inbound_acl:
                used.add(iface.inbound_acl)
            if iface.outbound_acl:
                used.add(iface.outbound_acl)
        if device.security.vty_access_class:
            used.add(device.security.vty_access_class)
        for nat in device.nat_rules:
            if nat.source_acl:
                used.add(nat.source_acl)

        return [
            Hit(
                subject=acl.name,
                description=(
                    f"Access list '{acl.name}' has {len(acl.entries)} entrie(s) defined but is "
                    "never applied to an interface, VTY line, or NAT rule - it has no effect on "
                    "any traffic."
                ),
            )
            for acl in device.acls
            # MikroTik firewall-filter rules are self-applying (a chain rule
            # *is* its own application) - only named/numbered ACLs that need
            # a separate apply step can be "dead" in this sense.
            if acl.kind != "firewall_filter" and acl.name not in used
        ]

    return Rule(
        rule_id="CONN-002",
        severity=Severity.LOW,
        vendor=None,
        category=Category.AVAILABILITY,
        title="Access list is defined but never applied",
        description="An ACL exists in the configuration but nothing references it, so it filters nothing.",
        recommendation="Apply the ACL to an interface, VTY line, or NAT rule, or remove it to reduce clutter.",
        check=check,
    )


def _orphan_vlan() -> Rule:
    def check(device: Device, raw_text: str) -> list[Hit]:
        used_vlan_ids: set[int] = set()
        for iface in device.interfaces:
            if iface.vlan:
                used_vlan_ids.add(iface.vlan)
            used_vlan_ids.update(iface.trunk_allowed_vlans)

        return [
            Hit(
                subject=f"VLAN {vlan.id}",
                description=(
                    f"VLAN {vlan.id}" + (f" ('{vlan.name}')" if vlan.name else "") + " is declared "
                    "but is not assigned to any access port and not allowed on any trunk."
                ),
            )
            for vlan in device.vlans
            if vlan.id not in used_vlan_ids
        ]

    return Rule(
        rule_id="CONN-003",
        severity=Severity.LOW,
        vendor=None,
        category=Category.CONFIG_QUALITY,
        title="VLAN is declared but never assigned to a port",
        description="A VLAN exists in the configuration but no interface actually uses it - configuration drift, not a functional break.",
        recommendation="Assign this VLAN to a port or trunk, or remove it if it's no longer needed.",
        check=check,
    )
