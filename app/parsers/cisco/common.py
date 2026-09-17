"""Shared Cisco IOS / IOS-XE config parsing.

`show running-config` output is organised as top-level statements, some of
which open an indented sub-block terminated implicitly by the next
non-indented line (or a bare `!`). This module splits the config into those
blocks and turns them into the normalized `Device` model. IOS and IOS-XE
share this logic almost completely; the two parser classes differ mainly in
vendor detection heuristics (see ios.py / iosxe.py).
"""

from __future__ import annotations

import re

from app.models.device import (
    AccessControlEntry,
    AccessControlList,
    Device,
    DHCPPool,
    Interface,
    InterfaceMode,
    IPv4Interface,
    ManagementService,
    NATRule,
    SecretType,
    StaticRoute,
    UserAccount,
    Vendor,
    Vlan,
)
from app.parsers.base import ParseResult, ParseWarning


def _mask_to_prefix(mask: str) -> int:
    octets = [int(o) for o in mask.split(".")]
    bits = "".join(f"{o:08b}" for o in octets)
    return bits.count("1")


def _split_blocks(raw_text: str) -> list[tuple[str, list[str]]]:
    blocks: list[tuple[str, list[str]]] = []
    for raw_line in raw_text.splitlines():
        line = raw_line.rstrip()
        if not line or line.strip() == "!" or line.strip() == "end":
            continue
        if not raw_line.startswith((" ", "\t")):
            blocks.append((line.strip(), []))
        else:
            if blocks:
                blocks[-1][1].append(line.strip())
    return blocks


_TYPE_DIGIT_TO_SECRET: dict[str, SecretType] = {
    "5": SecretType.CISCO_TYPE5,
    "7": SecretType.CISCO_TYPE7,
    "8": SecretType.CISCO_TYPE8,
    "9": SecretType.CISCO_TYPE9,
    "0": SecretType.PLAINTEXT,
}


def _secret_type_from_digit(digit: str | None) -> SecretType:
    if digit is None:
        return SecretType.PLAINTEXT
    return _TYPE_DIGIT_TO_SECRET.get(digit, SecretType.UNKNOWN_HASH)


def parse_cisco_config(raw_text: str, vendor: Vendor, platform_label: str) -> ParseResult:
    warnings: list[ParseWarning] = []
    device = Device(vendor=vendor, platform=platform_label)
    blocks = _split_blocks(raw_text)

    nat_inside_interfaces: set[str] = set()
    nat_outside_interfaces: set[str] = set()

    for header, sublines in blocks:
        try:
            _handle_block(device, header, sublines, nat_inside_interfaces, nat_outside_interfaces)
        except (AttributeError, IndexError, KeyError, TypeError, ValueError) as exc:
            warnings.append(ParseWarning(0, f"Could not parse block '{header}': {exc}"))
            device.unparsed_lines.append(header)

    for iface in device.interfaces:
        if iface.name in nat_inside_interfaces:
            iface.raw_block = (iface.raw_block or "") + "\n[nat: inside]"
        if iface.name in nat_outside_interfaces:
            iface.raw_block = (iface.raw_block or "") + "\n[nat: outside]"

    # Management services default to "not observed" unless we saw evidence.
    _finalize_management(device, raw_text)

    return ParseResult(device=device, warnings=warnings)


def _handle_block(
    device: Device,
    header: str,
    sublines: list[str],
    nat_inside_interfaces: set[str],
    nat_outside_interfaces: set[str],
) -> None:
    if header.startswith("hostname "):
        device.hostname = header.split(None, 1)[1].strip()
        return

    if header.startswith("interface "):
        _parse_interface(device, header, sublines, nat_inside_interfaces, nat_outside_interfaces)
        return

    if header.startswith("vlan ") and header.split()[1].isdigit():
        _parse_vlan(device, header, sublines)
        return

    if header.startswith("router "):
        parts = header.split(None, 2)
        proto_desc = " ".join(parts[1:]) if len(parts) > 1 else header
        device.routing.routing_protocols.append(proto_desc)
        return

    if header.startswith(("ip route ", "ipv6 route ")):
        _parse_static_route(device, header)
        return

    if header.startswith("ip access-list "):
        _parse_named_acl(device, header, sublines)
        return

    if header.startswith("access-list "):
        _parse_numbered_acl_line(device, header)
        return

    if header.startswith("ip dhcp pool "):
        _parse_dhcp_pool(device, header, sublines)
        return

    if header.startswith("ip nat inside source"):
        m = _NAT_LIST_RE.match(header)
        device.nat_rules.append(NATRule(kind="dynamic", source_acl=m.group(1) if m else None, raw=header))
        return

    if header.startswith(("ip nat inside", "ip nat outside")):
        return  # handled as part of interface blocks

    if header.startswith("username "):
        _parse_username(device, header)
        return

    if header.startswith(("enable secret", "enable password")):
        _parse_enable_secret(device, header)
        return

    if header.startswith("snmp-server community"):
        _parse_snmp_community(device, header)
        return

    if header.startswith("snmp-server"):
        device.snmp.enabled = True
        return

    if header.startswith(("ip name-server", "ip domain name-server")):
        device.dns_servers.extend(header.split()[2:])
        return

    if header.startswith("line "):
        _parse_line_block(device, header, sublines)
        return

    if header.startswith(("banner motd", "banner login")):
        device.security.login_banner_present = True
        return

    if header == "aaa new-model":
        device.security.aaa_new_model = True
        return

    if header == "service password-encryption":
        device.security.service_password_encryption = True
        return

    if header.startswith("ip default-gateway "):
        device.routing.default_gateway = header.split()[-1]
        return

    # Anything else (boot markers, logging, ntp server, etc.) is intentionally
    # not modeled yet - kept only in the raw view, never silently dropped.
    device.unparsed_lines.append(header)


_IFACE_IP_RE = re.compile(
    r"^ip address (\d{1,3}(?:\.\d{1,3}){3}) (\d{1,3}(?:\.\d{1,3}){3})(\s+secondary)?$"
)

# "ip nat inside source list <acl-name-or-number> ..." - captures the ACL
# reference so reference-integrity rules can confirm it actually exists.
_NAT_LIST_RE = re.compile(r"^ip nat inside source list (\S+)")


def _parse_interface(
    device: Device,
    header: str,
    sublines: list[str],
    nat_inside_interfaces: set[str],
    nat_outside_interfaces: set[str],
) -> None:
    name = header.split(None, 1)[1].strip()
    # `show running-config` never repeats an `interface X` header, but
    # hand-edited fragments or partial/merge configs sometimes do - merge
    # into the existing interface instead of creating a misleading ghost
    # duplicate with no IP/description that would falsely look "unused".
    existing = device.get_interface(name)
    iface = existing if existing is not None else Interface(name=name, enabled=True)
    iface.raw_block = ((iface.raw_block + "\n") if iface.raw_block else "") + "\n".join(sublines)

    for line in sublines:
        if line == "shutdown":
            iface.enabled = False
        elif line == "no shutdown":
            iface.enabled = True
        elif line.startswith("description "):
            iface.description = line.split(None, 1)[1]
        elif line.startswith("ip address"):
            if "dhcp" in line:
                continue
            m = _IFACE_IP_RE.match(line)
            if m:
                addr, mask, secondary = m.groups()
                iface.ipv4.append(
                    IPv4Interface(
                        address=addr,
                        prefix_length=_mask_to_prefix(mask),
                        secondary=bool(secondary),
                    )
                )
        elif line.startswith("switchport access vlan"):
            iface.mode = InterfaceMode.ACCESS
            iface.vlan = int(line.split()[-1])
        elif line.startswith("switchport mode trunk"):
            iface.mode = InterfaceMode.TRUNK
        elif line.startswith("switchport trunk allowed vlan"):
            vlan_spec = line.split(None, 4)[-1]
            for part in vlan_spec.split(","):
                part = part.strip()
                if part.isdigit() and int(part) not in iface.trunk_allowed_vlans:
                    iface.trunk_allowed_vlans.append(int(part))
        elif line.startswith("mtu "):
            iface.mtu = int(line.split()[-1])
        elif line == "ip nat inside":
            nat_inside_interfaces.add(name)
        elif line == "ip nat outside":
            nat_outside_interfaces.add(name)
        elif line.startswith("ip access-group"):
            # "ip access-group <name> <in|out>"
            parts = line.split()
            acl_name = parts[2] if len(parts) > 2 else ""
            direction = parts[3] if len(parts) > 3 else "in"
            if direction == "in":
                iface.inbound_acl = acl_name
            else:
                iface.outbound_acl = acl_name

    if iface.mode == InterfaceMode.UNKNOWN and iface.ipv4:
        iface.mode = InterfaceMode.ROUTED

    if existing is None:
        device.interfaces.append(iface)


def _parse_vlan(device: Device, header: str, sublines: list[str]) -> None:
    vlan_id = int(header.split()[1])
    name = None
    for line in sublines:
        if line.startswith("name "):
            name = line.split(None, 1)[1]
    device.vlans.append(Vlan(id=vlan_id, name=name))


def _parse_static_route(device: Device, header: str) -> None:
    parts = header.split()
    # ip route <network> <mask> <next-hop|interface> [metric]
    if len(parts) < 4:
        return
    network, mask, target = parts[2], parts[3], parts[4] if len(parts) > 4 else None
    if target is None:
        return
    prefix = _mask_to_prefix(mask) if "." in mask else int(mask)
    route = StaticRoute(network=network, prefix_length=prefix)
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
        route.next_hop = target
    else:
        route.interface = target
    remainder = parts[5:] if len(parts) > 5 else []
    if remainder and remainder[0].isdigit():
        route.metric = int(remainder[0])
    device.routing.static_routes.append(route)


def _parse_named_acl(device: Device, header: str, sublines: list[str]) -> None:
    parts = header.split()
    kind = "standard" if "standard" in header else "extended"
    name = parts[-1]
    acl = AccessControlList(name=name, kind=kind)  # type: ignore[arg-type]
    for seq, line in enumerate(sublines, start=10):
        acl.entries.append(_parse_ace_line(line, seq))
    device.acls.append(acl)


def _parse_numbered_acl_line(device: Device, header: str) -> None:
    parts = header.split(None, 2)
    if len(parts) < 3:
        return
    number = parts[1]
    rest = parts[2]
    acl = next((a for a in device.acls if a.name == number), None)
    if acl is None:
        kind = "standard" if 1 <= int(number.split()[0]) <= 99 or (1300 <= int(number) <= 1999) else "extended"
        acl = AccessControlList(name=number, kind=kind)  # type: ignore[arg-type]
        device.acls.append(acl)
    acl.entries.append(_parse_ace_line(rest, len(acl.entries) * 10 + 10))


def _consume_acl_address(tokens: list[str], index: int) -> tuple[str, int]:
    """Consume one Cisco ACL address specification starting at `index`.

    Handles the three forms IOS accepts: `any` (1 token), `host <ip>`
    (2 tokens), and `<network> <wildcard-mask>` (2 tokens). Returns the
    address text and the index of the next unconsumed token.
    """
    if index >= len(tokens):
        return "any", index
    if tokens[index] == "any":
        return "any", index + 1
    if tokens[index] == "host" and index + 1 < len(tokens):
        return f"host {tokens[index + 1]}", index + 2
    if index + 1 < len(tokens) and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", tokens[index + 1]):
        return f"{tokens[index]} {tokens[index + 1]}", index + 2
    return tokens[index], index + 1


def _parse_ace_line(line: str, seq: int) -> AccessControlEntry:
    tokens = line.split()
    action = tokens[0] if tokens and tokens[0] in ("permit", "deny") else "permit"
    protocol = tokens[1] if len(tokens) > 1 else "ip"
    source, next_index = _consume_acl_address(tokens, 2)
    destination, _ = _consume_acl_address(tokens, next_index)
    return AccessControlEntry(
        sequence=seq,
        action=action,  # type: ignore[arg-type]
        protocol=protocol,
        source=source or "any",
        destination=destination or "any",
        raw=line,
    )


def _parse_dhcp_pool(device: Device, header: str, sublines: list[str]) -> None:
    name = header.split()[-1]
    pool = DHCPPool(name=name)
    for line in sublines:
        if line.startswith("network "):
            parts = line.split()
            pool.network = parts[1]
            if len(parts) > 2 and "." in parts[2]:
                pool.prefix_length = _mask_to_prefix(parts[2])
        elif line.startswith("default-router "):
            pool.gateway = line.split()[-1]
        elif line.startswith("dns-server"):
            pool.dns_servers.extend(line.split()[1:])
        elif line.startswith("lease "):
            pool.lease_time = line.split(None, 1)[1]
    device.dhcp_pools.append(pool)


def _parse_username(device: Device, header: str) -> None:
    m = re.match(
        r"username (\S+)(?: privilege (\d+))?(?: .*?)?\s(secret|password) (?:(\d+) )?(\S+)$",
        header,
    )
    if not m:
        return
    username, privilege, _kind, digit, token = m.groups()
    device.users.append(
        UserAccount(
            username=username,
            privilege=int(privilege) if privilege else None,
            secret_type=_secret_type_from_digit(digit),
            secret_raw=token,
        )
    )


def _parse_enable_secret(device: Device, header: str) -> None:
    m = re.match(r"enable (?:secret|password) (?:level \d+ )?(?:(\d+) )?(\S+)$", header)
    if not m:
        return
    digit, token = m.groups()
    device.security.enable_secret = UserAccount(
        username="enable",
        secret_type=_secret_type_from_digit(digit),
        secret_raw=token,
    )


def _parse_snmp_community(device: Device, header: str) -> None:
    parts = header.split()
    community = parts[2] if len(parts) > 2 else ""
    device.snmp.enabled = True
    device.snmp.communities.append(community)


def _parse_line_block(device: Device, header: str, sublines: list[str]) -> None:
    line_type = header.split()[1] if len(header.split()) > 1 else ""
    transports: list[str] = []
    access_class: str | None = None
    for line in sublines:
        if line.startswith("transport input"):
            transports = line.split()[2:]
        elif line.startswith("access-class "):
            parts = line.split()
            access_class = parts[1] if len(parts) > 1 else None
    if line_type == "vty":
        device.management.append(
            ManagementService(name="telnet", enabled="telnet" in transports)
        )
        device.management.append(
            ManagementService(name="ssh", enabled="ssh" in transports)
        )
        if access_class:
            device.security.vty_access_class = access_class


def _finalize_management(device: Device, raw_text: str) -> None:
    has_http = bool(re.search(r"^ip http server", raw_text, re.MULTILINE))
    has_https = bool(re.search(r"^ip http secure-server", raw_text, re.MULTILINE))
    device.management.append(ManagementService(name="http", enabled=has_http))
    device.management.append(ManagementService(name="https", enabled=has_https))

    has_ssh_config = bool(re.search(r"^ip ssh version", raw_text, re.MULTILINE)) or any(
        u.secret_type != SecretType.UNKNOWN_HASH for u in device.users
    )
    # Refine ssh service entry already added from vty lines, if any
    if not any(m.name == "ssh" for m in device.management):
        device.management.append(ManagementService(name="ssh", enabled=has_ssh_config))
    if not any(m.name == "telnet" for m in device.management):
        device.management.append(ManagementService(name="telnet", enabled=False))
