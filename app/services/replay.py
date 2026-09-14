"""Dependency-aware reconstruction plans; never CLI history recovery.

A `show running-config` / `/export` does not contain the sequence of CLI
commands an engineer actually typed - that history simply isn't stored on
the device. What this module builds instead is a *logical* order that would
reproduce the resulting configuration on a clean device, grouped the way the
project spec lays out: global prerequisites, interfaces, VLANs, addressing,
routing, ACL/firewall, NAT, services, then management/hardening. Every step
carries an explanation, its dependencies, and a rough risk level so an
engineer can sanity-check it before typing anything into a live device.
"""

from __future__ import annotations

from app.models.device import Device, Vendor
from app.renderers.cisco_common import prefix_to_mask

_ReplayStep = dict[str, object]


class _StepBuilder:
    def __init__(self) -> None:
        self.steps: list[_ReplayStep] = []

    def add(
        self,
        command: str,
        explanation: str,
        depends_on: list[str] | None = None,
        risk: str = "LOW",
    ) -> None:
        self.steps.append(
            {
                "step": len(self.steps) + 1,
                "command": command,
                "explanation": explanation,
                "dependencies": depends_on or [],
                "risk": risk,
            }
        )


def build_replay_plan(device: Device) -> list[_ReplayStep]:
    if device.vendor in (Vendor.CISCO_IOS, Vendor.CISCO_IOS_XE):
        return _build_cisco_plan(device)
    return _build_mikrotik_plan(device)


def _build_cisco_plan(device: Device) -> list[_ReplayStep]:
    b = _StepBuilder()

    # --- Global prerequisites -------------------------------------------------
    b.add("configure terminal", "Enter global configuration mode.")
    if device.hostname:
        b.add(f"hostname {device.hostname}", "Set the device identity.", ["configure terminal"])
    if device.security.enable_secret:
        secret = device.security.enable_secret
        b.add(
            f"enable secret {secret.secret_raw}",
            "Protect privileged EXEC access before anything else is configured.",
            ["configure terminal"],
            "HIGH",
        )
    if device.security.service_password_encryption:
        b.add("service password-encryption", "Obfuscate clear-text line passwords.", risk="LOW")
    if device.security.aaa_new_model:
        b.add("aaa new-model", "Enable AAA before referencing method lists elsewhere.", risk="MEDIUM")
    for user in device.users:
        priv = f" privilege {user.privilege}" if user.privilege is not None else ""
        b.add(
            f"username {user.username}{priv} secret {user.secret_raw}",
            f"Create local account '{user.username}'.",
            risk="MEDIUM",
        )

    # --- VLANs ------------------------------------------------------------
    for vlan in device.vlans:
        b.add(f"vlan {vlan.id}", f"Create VLAN {vlan.id}.")
        if vlan.name:
            b.add(f"name {vlan.name}", "Name the VLAN.", [f"vlan {vlan.id}"])
        b.add("exit", "Return to global configuration mode.")

    # --- Interfaces + IP addressing ---------------------------------------
    for iface in device.interfaces:
        b.add(f"interface {iface.name}", "Create or select the interface.")
        if iface.description:
            b.add(
                f"description {iface.description}",
                "Document the interface's purpose for future engineers.",
                [f"interface {iface.name}"],
            )
        if iface.mode.value == "access" and iface.vlan:
            b.add("switchport mode access", "Set access mode.", [f"interface {iface.name}"])
            b.add(
                f"switchport access vlan {iface.vlan}",
                "Assign the access VLAN.",
                [f"vlan {iface.vlan}", f"interface {iface.name}"],
            )
        elif iface.mode.value == "trunk":
            b.add("switchport mode trunk", "Set trunk mode.", [f"interface {iface.name}"])
            if iface.trunk_allowed_vlans:
                vlans_str = ",".join(str(v) for v in iface.trunk_allowed_vlans)
                b.add(
                    f"switchport trunk allowed vlan {vlans_str}",
                    "Restrict the trunk to the VLANs actually in use.",
                    [f"interface {iface.name}"],
                )
        for address in iface.ipv4:
            mask = prefix_to_mask(address.prefix_length)
            secondary = " secondary" if address.secondary else ""
            b.add(
                f"ip address {address.address} {mask}{secondary}",
                "Assign IPv4 addressing.",
                [f"interface {iface.name}"],
                "MEDIUM",
            )
        if iface.inbound_acl:
            b.add(
                f"ip access-group {iface.inbound_acl} in",
                "Apply the inbound ACL.",
                [f"interface {iface.name}", f"acl {iface.inbound_acl}"],
                "HIGH",
            )
        if iface.outbound_acl:
            b.add(
                f"ip access-group {iface.outbound_acl} out",
                "Apply the outbound ACL.",
                [f"interface {iface.name}", f"acl {iface.outbound_acl}"],
                "HIGH",
            )
        b.add(
            "no shutdown" if iface.enabled else "shutdown",
            "Apply the interface's administrative state.",
            [f"interface {iface.name}"],
            "MEDIUM",
        )
        b.add("exit", "Return to global configuration mode.")

    # --- Routing ------------------------------------------------------------
    for route in device.routing.static_routes:
        mask = prefix_to_mask(route.prefix_length)
        target = route.next_hop or route.interface or "<next-hop>"
        b.add(
            f"ip route {route.network} {mask} {target}",
            "Install a static route.",
            ["IP addressing"],
            "MEDIUM",
        )
    for protocol in device.routing.routing_protocols:
        b.add(f"router {protocol}", "Enable a dynamic routing protocol.", ["IP addressing"], "HIGH")
        b.add("exit", "Return to global configuration mode.")

    # --- ACL / firewall -------------------------------------------------
    for acl in device.acls:
        if acl.kind != "extended":
            continue
        b.add(f"ip access-list extended {acl.name}", f"Define ACL '{acl.name}'.")
        for entry in acl.entries:
            b.add(
                f"{entry.action} {entry.protocol} {entry.source} {entry.destination}",
                "Add an access control entry.",
                [f"acl {acl.name}"],
                "HIGH",
            )
        b.add("exit", "Return to global configuration mode.")

    # --- NAT ------------------------------------------------------------
    for nat in device.nat_rules:
        b.add(nat.raw or "ip nat inside source ...", "Configure NAT translation.", risk="MEDIUM")

    # --- Services (DHCP, SNMP) --------------------------------------------
    for pool in device.dhcp_pools:
        b.add(f"ip dhcp pool {pool.name}", f"Create DHCP pool '{pool.name}'.")
        if pool.network and pool.prefix_length:
            mask = prefix_to_mask(pool.prefix_length)
            b.add(f"network {pool.network} {mask}", "Scope the pool to its subnet.", [f"ip dhcp pool {pool.name}"])
        if pool.gateway:
            b.add(f"default-router {pool.gateway}", "Advertise the default gateway.", [f"ip dhcp pool {pool.name}"])
        if pool.dns_servers:
            b.add(
                f"dns-server {' '.join(pool.dns_servers)}",
                "Advertise DNS servers to DHCP clients.",
                [f"ip dhcp pool {pool.name}"],
            )
        b.add("exit", "Return to global configuration mode.")

    if device.snmp.enabled:
        for community in device.snmp.communities:
            b.add(
                f"snmp-server community {community} RO",
                "Enable read-only SNMP access.",
                risk="HIGH" if community in ("public", "private") else "MEDIUM",
            )

    # --- Management / hardening -------------------------------------------
    for svc in device.management:
        if svc.name == "http":
            b.add(
                "ip http server" if svc.enabled else "no ip http server",
                "Set the plain-HTTP management listener state.",
                risk="MEDIUM" if svc.enabled else "LOW",
            )
        elif svc.name == "https":
            b.add(
                "ip http secure-server" if svc.enabled else "no ip http secure-server",
                "Set the HTTPS management listener state.",
            )
    if device.security.login_banner_present:
        b.add(
            "banner motd ^C Unauthorized access is prohibited. ^C",
            "Add an authorized-access banner (common compliance requirement).",
        )
    b.add("line con 0", "Select the console line.")
    b.add("exit", "Return to global configuration mode.")
    b.add("line vty 0 4", "Select the VTY (remote management) lines.")
    transports = [
        m.name for m in device.management if m.name in ("ssh", "telnet") and m.enabled
    ]
    if transports:
        b.add(
            f"transport input {' '.join(transports)}",
            "Restrict which protocols may reach VTY lines.",
            ["line vty 0 4"],
            "HIGH" if "telnet" in transports else "MEDIUM",
        )
    if device.security.vty_access_class:
        b.add(
            f"access-class {device.security.vty_access_class} in",
            "Restrict which sources may reach VTY lines.",
            ["line vty 0 4", f"acl {device.security.vty_access_class}"],
            "HIGH",
        )
    b.add("end", "Leave configuration mode.")
    return b.steps


def _build_mikrotik_plan(device: Device) -> list[_ReplayStep]:
    b = _StepBuilder()

    if device.hostname:
        b.add(f"/system identity set name={device.hostname}", "Set the device identity.")

    for vlan in device.vlans:
        parent = vlan.interfaces[0] if vlan.interfaces else "bridge1"
        b.add(
            f"/interface vlan add name={vlan.name or f'vlan{vlan.id}'} vlan-id={vlan.id} interface={parent}",
            f"Create VLAN {vlan.id}.",
            [f"interface {parent}"],
        )

    for iface in device.interfaces:
        if not iface.enabled:
            b.add(
                f"/interface ethernet set [ find default-name={iface.name} ] disabled=yes",
                "Administratively disable an unused interface.",
                risk="LOW",
            )
        for address in iface.ipv4:
            b.add(
                f"/ip address add address={address.address}/{address.prefix_length} interface={iface.name}",
                "Assign IPv4 addressing.",
                [f"interface {iface.name}"],
                "MEDIUM",
            )

    for route in device.routing.static_routes:
        target = route.next_hop or route.interface or "<gateway>"
        b.add(
            f"/ip route add dst-address={route.network}/{route.prefix_length} gateway={target}",
            "Install a static route.",
            ["IP addressing"],
            "MEDIUM",
        )

    filter_acl = next((a for a in device.acls if a.kind == "firewall_filter"), None)
    if filter_acl:
        for entry in filter_acl.entries:
            action = "accept" if entry.action == "permit" else "drop"
            b.add(
                f"/ip firewall filter add chain=input action={action} "
                f"src-address={entry.source} dst-address={entry.destination}",
                "Add a firewall filter rule (input chain rules apply in order).",
                risk="HIGH",
            )

    for nat in device.nat_rules:
        out_if = f" out-interface={nat.interface}" if nat.interface else ""
        b.add(
            f"/ip firewall nat add chain=srcnat action={nat.kind}{out_if}",
            "Configure NAT translation.",
            risk="MEDIUM",
        )

    for pool in device.dhcp_pools:
        if pool.range_start and pool.range_end:
            b.add(
                f"/ip pool add name={pool.name}_pool ranges={pool.range_start}-{pool.range_end}",
                f"Define the address pool backing DHCP server '{pool.name}'.",
            )
        b.add(
            f"/ip dhcp-server add address-pool={pool.name}_pool interface=bridge1 name={pool.name}",
            "Bind the DHCP server to its pool and interface.",
            [f"{pool.name}_pool"],
        )
        if pool.network and pool.prefix_length:
            gw = f" gateway={pool.gateway}" if pool.gateway else ""
            dns = f" dns-server={','.join(pool.dns_servers)}" if pool.dns_servers else ""
            b.add(
                f"/ip dhcp-server network add address={pool.network}/{pool.prefix_length}{gw}{dns}",
                "Describe the network options handed out by DHCP.",
                [f"{pool.name}"],
            )

    if device.dns_servers:
        b.add(f"/ip dns set servers={','.join(device.dns_servers)}", "Configure upstream DNS resolvers.")

    for community in device.snmp.communities:
        b.add(
            f"/snmp community add name={community}",
            "Create an SNMP community.",
            risk="HIGH" if community == "public" else "MEDIUM",
        )

    for svc in device.management:
        disabled = "no" if svc.enabled else "yes"
        addr = f" address={','.join(svc.allowed_sources)}" if svc.allowed_sources else ""
        risk = "HIGH" if svc.enabled and not svc.allowed_sources and svc.name in ("winbox", "ssh", "api") else "LOW"
        b.add(
            f"/ip service set {svc.name} disabled={disabled}{addr}",
            f"Set the '{svc.name}' management service state and source restriction.",
            risk=risk,
        )

    for user in device.users:
        if user.group == "ppp":
            b.add(
                f"/ppp secret add name={user.username} password={user.secret_raw} service=any",
                "Create a PPP secret.",
                risk="MEDIUM",
            )
        else:
            b.add(
                f"/user add name={user.username} group={user.group or 'read'}",
                "Create a local user account.",
                risk="MEDIUM",
            )

    return b.steps
