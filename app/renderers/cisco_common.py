from __future__ import annotations

import ipaddress

from app.models.device import Device, SecretType


def prefix_to_mask(prefix_length: int) -> str:
    """Convert a CIDR prefix length to a dotted-decimal subnet mask.

    Shared by the renderer and the replay-plan builder so both always emit
    the same (correct) `ip address <addr> <mask>` syntax instead of Cisco
    IOS incorrectly being given a `/24`-style suffix.
    """
    return str(ipaddress.IPv4Network((0, prefix_length)).netmask)


# Backwards-compatible private alias for any in-module callers.
_prefix_to_mask = prefix_to_mask


_SECRET_DIGIT = {
    SecretType.PLAINTEXT: "0",
    SecretType.CISCO_TYPE7: "7",
    SecretType.CISCO_TYPE5: "5",
    SecretType.CISCO_TYPE8: "8",
    SecretType.CISCO_TYPE9: "9",
    SecretType.UNKNOWN_HASH: "5",
}


def render_cisco_config(device: Device, header_comment: str) -> str:
    lines: list[str] = [header_comment, "!"]

    if device.hostname:
        lines.append(f"hostname {device.hostname}")
        lines.append("!")

    if device.security.enable_secret:
        secret = device.security.enable_secret
        digit = _SECRET_DIGIT.get(secret.secret_type, "5")
        lines.append(f"enable secret {digit} {secret.secret_raw}")
        lines.append("!")

    if device.security.aaa_new_model:
        lines.append("aaa new-model")
    if device.security.service_password_encryption:
        lines.append("service password-encryption")
    if device.security.aaa_new_model or device.security.service_password_encryption:
        lines.append("!")

    for user in device.users:
        digit = _SECRET_DIGIT.get(user.secret_type, "5")
        priv = f" privilege {user.privilege}" if user.privilege is not None else ""
        lines.append(f"username {user.username}{priv} secret {digit} {user.secret_raw}")
    if device.users:
        lines.append("!")

    for vlan in device.vlans:
        lines.append(f"vlan {vlan.id}")
        if vlan.name:
            lines.append(f" name {vlan.name}")
        lines.append("!")

    for iface in device.interfaces:
        lines.append(f"interface {iface.name}")
        if iface.description:
            lines.append(f" description {iface.description}")
        if iface.mode.value == "access" and iface.vlan:
            lines.append(" switchport mode access")
            lines.append(f" switchport access vlan {iface.vlan}")
        elif iface.mode.value == "trunk":
            lines.append(" switchport mode trunk")
            if iface.trunk_allowed_vlans:
                vlans_str = ",".join(str(v) for v in iface.trunk_allowed_vlans)
                lines.append(f" switchport trunk allowed vlan {vlans_str}")
        for ipv4 in iface.ipv4:
            mask = _prefix_to_mask(ipv4.prefix_length)
            secondary = " secondary" if ipv4.secondary else ""
            lines.append(f" ip address {ipv4.address} {mask}{secondary}")
        if iface.mtu:
            lines.append(f" mtu {iface.mtu}")
        if iface.inbound_acl:
            lines.append(f" ip access-group {iface.inbound_acl} in")
        if iface.outbound_acl:
            lines.append(f" ip access-group {iface.outbound_acl} out")
        lines.append(" shutdown" if not iface.enabled else " no shutdown")
        lines.append("!")

    for route in device.routing.static_routes:
        mask = _prefix_to_mask(route.prefix_length)
        target = route.next_hop or route.interface or ""
        metric = f" {route.metric}" if route.metric is not None else ""
        lines.append(f"ip route {route.network} {mask} {target}{metric}".rstrip())
    if device.routing.static_routes:
        lines.append("!")

    for acl in device.acls:
        if acl.kind == "extended":
            lines.append(f"ip access-list extended {acl.name}")
            for entry in acl.entries:
                lines.append(f" {entry.action} {entry.protocol} {entry.source} {entry.destination}")
            lines.append("!")

    for pool in device.dhcp_pools:
        lines.append(f"ip dhcp pool {pool.name}")
        if pool.network and pool.prefix_length:
            mask = _prefix_to_mask(pool.prefix_length)
            lines.append(f" network {pool.network} {mask}")
        if pool.gateway:
            lines.append(f" default-router {pool.gateway}")
        if pool.dns_servers:
            lines.append(f" dns-server {' '.join(pool.dns_servers)}")
        lines.append("!")

    if device.snmp.enabled:
        for community in device.snmp.communities:
            lines.append(f"snmp-server community {community} RO")
        lines.append("!")

    for svc in device.management:
        if svc.name == "http":
            lines.append("ip http server" if svc.enabled else "no ip http server")
        elif svc.name == "https":
            lines.append("ip http secure-server" if svc.enabled else "no ip http secure-server")
    lines.append("!")

    if device.security.login_banner_present:
        lines.append("banner motd ^C Unauthorized access is prohibited. ^C")
        lines.append("!")

    lines.append("line con 0")
    lines.append("line vty 0 4")
    transports = []
    if any(m.name == "ssh" and m.enabled for m in device.management):
        transports.append("ssh")
    if any(m.name == "telnet" and m.enabled for m in device.management):
        transports.append("telnet")
    if transports:
        lines.append(f" transport input {' '.join(transports)}")
    if device.security.vty_access_class:
        lines.append(f" access-class {device.security.vty_access_class} in")
    lines.append("!")

    lines.append("end")
    return "\n".join(lines) + "\n"
