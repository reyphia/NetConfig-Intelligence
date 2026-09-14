"""MikroTik RouterOS `/export` parser.

RouterOS export syntax is command-based rather than indentation-based:
a `/path/to/section` line sets the current context, and the `add` / `set` /
`remove` lines that follow (until the next `/...` line) apply to it. This is
quite different from Cisco's block style, which is exactly why vendor
parsing lives behind the `ConfigParser` plugin boundary instead of being
shared logic.

RouterOS syntax is large; this parser covers the sections that matter for
security auditing and safe editing (interfaces, addressing, routing,
firewall/NAT, DHCP, DNS, management services, SNMP, users/PPP secrets) and
keeps everything else in `unparsed_lines` rather than guessing.
"""

from __future__ import annotations

import ipaddress
import re

from app.models.device import (
    AccessControlEntry,
    AccessControlList,
    Device,
    DHCPPool,
    Interface,
    IPv4Interface,
    ManagementService,
    NATRule,
    SecretType,
    StaticRoute,
    UserAccount,
    Vendor,
    Vlan,
)
from app.parsers.base import ConfigParser, ParseResult, ParseWarning

_SECTION_RE = re.compile(r"^/\S.*$")
_KV_RE = re.compile(r'([\w.\-]+)=("([^"]*)"|(\S+))')
_BRACKET_RE = re.compile(r"\[[^\]]*\]")

# Services enabled out of the box on a factory-default RouterOS install.
# This is an approximation used only when a service is never explicitly
# `set` in the export - it lets the analyzer flag exposure that the admin
# may not realise is still there.
_DEFAULT_ENABLED_SERVICES = {"telnet", "ftp", "www", "ssh", "winbox", "api"}
_DEFAULT_DISABLED_SERVICES = {"www-ssl", "api-ssl"}


def _strip_selector(line: str) -> str:
    """Remove `[ find ... ]` selector expressions so kv parsing doesn't choke on them."""
    return _BRACKET_RE.sub(" ", line)


def _parse_kv(line: str) -> dict[str, str]:
    clean = _strip_selector(line)
    result: dict[str, str] = {}
    for match in _KV_RE.finditer(clean):
        key = match.group(1)
        value = match.group(3) if match.group(3) is not None else match.group(4)
        result[key] = value
    return result


def _find_default_name(line: str) -> str | None:
    m = re.search(r"default-name=(\S+)", line)
    return m.group(1) if m else None


def _split_sections(raw_text: str) -> list[tuple[str, str]]:
    """Return a list of (current_section_path, line) pairs, comments dropped."""
    out: list[tuple[str, str]] = []
    current = ""
    for raw_line in raw_text.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if _SECTION_RE.match(stripped):
            current = stripped
            continue
        out.append((current, stripped))
    return out


def _get_or_create_interface(device: Device, name: str) -> Interface:
    iface = device.get_interface(name)
    if iface is None:
        iface = Interface(name=name, enabled=True)
        device.interfaces.append(iface)
    return iface


def parse_routeros_config(raw_text: str) -> ParseResult:
    warnings: list[ParseWarning] = []
    device = Device(vendor=Vendor.MIKROTIK_ROUTEROS, platform="MikroTik RouterOS")

    pools: dict[str, dict[str, str]] = {}
    dhcp_server_defs: list[dict[str, str]] = []
    dhcp_network_defs: list[dict[str, str]] = []
    filter_acl = AccessControlList(name="filter", kind="firewall_filter")

    for section, line in _split_sections(raw_text):
        try:
            kv = _parse_kv(line)
            action = line.split()[0] if line.split() else ""

            if section.startswith("/system identity"):
                if "name" in kv:
                    device.hostname = kv["name"]

            elif section in ("/interface bridge", "/interface ethernet", "/interface wireless"):
                name = kv.get("name") or _find_default_name(line)
                if not name:
                    continue
                iface = _get_or_create_interface(device, name)
                if "comment" in kv:
                    iface.description = kv["comment"]
                if kv.get("disabled") == "yes":
                    iface.enabled = False

            elif section == "/interface vlan":
                name = kv.get("name")
                vlan_id = kv.get("vlan-id")
                parent = kv.get("interface")
                if name and vlan_id and vlan_id.isdigit():
                    vlan = Vlan(id=int(vlan_id), name=name, interfaces=[parent] if parent else [])
                    device.vlans.append(vlan)
                    iface = _get_or_create_interface(device, name)
                    iface.vlan = int(vlan_id)

            elif section == "/ip address":
                addr = kv.get("address")
                iface_name = kv.get("interface")
                if addr and iface_name and "/" in addr:
                    ip_part, prefix_part = addr.split("/", 1)
                    iface = _get_or_create_interface(device, iface_name)
                    iface.ipv4.append(IPv4Interface(address=ip_part, prefix_length=int(prefix_part)))

            elif section == "/ip route":
                dst = kv.get("dst-address", "0.0.0.0/0")
                gateway = kv.get("gateway")
                distance = kv.get("distance")
                net, prefix = (dst.split("/", 1) + ["32"])[:2] if "/" in dst else (dst, "32")
                route = StaticRoute(
                    network=net,
                    prefix_length=int(prefix),
                    next_hop=gateway if gateway and not gateway.isalpha() else None,
                    interface=gateway if gateway and gateway.isalpha() else None,
                    metric=int(distance) if distance and distance.isdigit() else None,
                )
                device.routing.static_routes.append(route)

            elif section == "/ip firewall filter" and action == "add":
                chain = kv.get("chain", "input")
                raw_action = kv.get("action", "accept")
                mapped = "permit" if raw_action in ("accept",) else "deny"
                filter_acl.entries.append(
                    AccessControlEntry(
                        action=mapped,  # type: ignore[arg-type]
                        protocol=kv.get("protocol", "ip"),
                        source=kv.get("src-address", "any"),
                        destination=kv.get("dst-address", "any"),
                        raw=f"chain={chain} {line}",
                    )
                )

            elif section == "/ip firewall nat" and action == "add":
                device.nat_rules.append(
                    NATRule(
                        kind=kv.get("action", "masquerade"),  # type: ignore[arg-type]
                        source=kv.get("src-address"),
                        destination=kv.get("dst-address"),
                        interface=kv.get("out-interface"),
                        raw=line,
                    )
                )

            elif section == "/ip pool" and action == "add" and "name" in kv:
                pools[kv["name"]] = kv

            elif section == "/ip dhcp-server" and action == "add":
                dhcp_server_defs.append(kv)

            elif section == "/ip dhcp-server network" and action == "add":
                dhcp_network_defs.append(kv)

            elif section == "/ip dns":
                servers = kv.get("servers")
                if servers:
                    device.dns_servers.extend(s.strip() for s in servers.split(","))

            elif section == "/ip service" and action == "set":
                tokens = line.split()
                service_name = tokens[1] if len(tokens) > 1 else kv.get("name")
                if service_name:
                    disabled = kv.get("disabled")
                    enabled = (
                        disabled != "yes"
                        if disabled is not None
                        else service_name in _DEFAULT_ENABLED_SERVICES
                    )
                    device.management.append(
                        ManagementService(
                            name=service_name,
                            enabled=enabled,
                            allowed_sources=(
                                kv["address"].split(",") if "address" in kv else []
                            ),
                        )
                    )

            elif section == "/snmp community" and "name" in kv:
                device.snmp.enabled = True
                device.snmp.communities.append(kv["name"])

            elif section == "/snmp" and action == "set":
                if kv.get("enabled") == "yes":
                    device.snmp.enabled = True

            elif section == "/ppp secret" and action == "add":
                name = kv.get("name")
                password = kv.get("password")
                if name and password:
                    device.users.append(
                        UserAccount(
                            username=name,
                            secret_type=SecretType.PLAINTEXT,
                            secret_raw=password,
                            group="ppp",
                        )
                    )

            elif section == "/user" and action == "add":
                name = kv.get("name")
                if name:
                    device.users.append(
                        UserAccount(
                            username=name,
                            secret_type=SecretType.PLAINTEXT if "password" in kv else SecretType.UNKNOWN_HASH,
                            secret_raw=kv.get("password", ""),
                            group=kv.get("group"),
                        )
                    )

            else:
                if section:
                    device.unparsed_lines.append(f"{section}: {line}")
                else:
                    device.unparsed_lines.append(line)

        except (AttributeError, IndexError, KeyError, TypeError, ValueError) as exc:
            warnings.append(ParseWarning(0, f"Could not parse '{line}' in {section}: {exc}"))

    if filter_acl.entries:
        device.acls.append(filter_acl)

    _link_dhcp_pools(device, pools, dhcp_server_defs, dhcp_network_defs)

    return ParseResult(device=device, warnings=warnings)


def _link_dhcp_pools(
    device: Device,
    pools: dict[str, dict[str, str]],
    dhcp_server_defs: list[dict[str, str]],
    dhcp_network_defs: list[dict[str, str]],
) -> None:
    for server in dhcp_server_defs:
        pool_name = server.get("address-pool")
        server_name = server.get("name", pool_name or "dhcp")
        pool_kv = pools.get(pool_name or "", {})
        dhcp_pool = DHCPPool(name=server_name)

        ranges = pool_kv.get("ranges")
        if ranges:
            first_range = ranges.split(",")[0]
            if "-" in first_range:
                start, end = first_range.split("-", 1)
                dhcp_pool.range_start = start
                dhcp_pool.range_end = end

        matching_network = _match_network_for_range(dhcp_pool.range_start, dhcp_network_defs)
        if matching_network:
            addr = matching_network.get("address", "")
            if "/" in addr:
                net, prefix = addr.split("/", 1)
                dhcp_pool.network = net
                dhcp_pool.prefix_length = int(prefix)
            if "gateway" in matching_network:
                dhcp_pool.gateway = matching_network["gateway"]
            if "dns-server" in matching_network:
                dhcp_pool.dns_servers = [s.strip() for s in matching_network["dns-server"].split(",")]

        device.dhcp_pools.append(dhcp_pool)


def _match_network_for_range(
    range_start: str | None, dhcp_network_defs: list[dict[str, str]]
) -> dict[str, str] | None:
    if not range_start or not dhcp_network_defs:
        return dhcp_network_defs[0] if dhcp_network_defs else None
    try:
        ip = ipaddress.IPv4Address(range_start)
    except ValueError:
        return dhcp_network_defs[0] if dhcp_network_defs else None
    for net_def in dhcp_network_defs:
        addr = net_def.get("address", "")
        if "/" not in addr:
            continue
        try:
            network = ipaddress.IPv4Network(addr, strict=False)
        except ValueError:
            continue
        if ip in network:
            return net_def
    return dhcp_network_defs[0] if dhcp_network_defs else None


_ROS_MARKERS = re.compile(
    r"^/interface |^/ip address|^/ip firewall|^/system identity|^/ip service|RouterOS",
    re.MULTILINE,
)


class MikroTikRouterOSParser(ConfigParser):
    vendor = Vendor.MIKROTIK_ROUTEROS
    platform_label = "MikroTik RouterOS"

    def parse(self, raw_text: str) -> ParseResult:
        return parse_routeros_config(raw_text)

    @classmethod
    def detection_score(cls, raw_text: str) -> float:
        hits = len(_ROS_MARKERS.findall(raw_text))
        if hits == 0:
            return 0.0
        score = 0.5 + min(hits * 0.08, 0.45)
        if re.search(r"# software id =|# model =", raw_text):
            score += 0.1
        return max(0.0, min(score, 0.98))
