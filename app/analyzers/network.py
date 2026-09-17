"""IPv4 network calculator and cross-configuration consistency checks.

This module is deliberately independent from any vendor - it operates on
plain addresses/prefixes pulled out of the normalized `Device` model, using
Python's standard `ipaddress` module for all arithmetic (no home-grown CIDR
math, which is where subtle bugs like off-by-one broadcast addresses creep
in).
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from app.models.device import Device
from app.models.findings import Category, Finding, Severity


@dataclass
class NetworkSummary:
    cidr: str
    network: str
    prefix_length: int
    netmask: str
    usable_hosts: int
    first_host: str | None
    last_host: str | None
    broadcast: str | None
    gateway: str | None
    utilization_percent: float | None
    source: str  # where this network came from, e.g. "interface Gi0/0"


@dataclass
class NetworkIssue:
    severity: str  # LOW / MEDIUM / HIGH / CRITICAL - consistent with Severity enum values
    title: str
    description: str
    recommendation: str
    rule_id: str
    category: Category
    subject: str | None = None


@dataclass
class NetworkAnalysis:
    networks: list[NetworkSummary] = field(default_factory=list)
    issues: list[NetworkIssue] = field(default_factory=list)


def _safe_network(address: str, prefix_length: int) -> ipaddress.IPv4Network | None:
    try:
        return ipaddress.IPv4Network(f"{address}/{prefix_length}", strict=False)
    except ValueError:
        return None


def summarize_network(address: str, prefix_length: int, gateway: str | None, source: str) -> NetworkSummary | None:
    net = _safe_network(address, prefix_length)
    if net is None:
        return None
    hosts = list(net.hosts()) if prefix_length < 31 else []
    first = str(hosts[0]) if hosts else None
    last = str(hosts[-1]) if hosts else None
    usable = net.num_addresses - 2 if prefix_length < 31 else net.num_addresses
    utilization = None
    return NetworkSummary(
        cidr=str(net),
        network=str(net.network_address),
        prefix_length=prefix_length,
        netmask=str(net.netmask),
        usable_hosts=max(usable, 0),
        first_host=first,
        last_host=last,
        broadcast=str(net.broadcast_address) if prefix_length < 31 else None,
        gateway=gateway,
        utilization_percent=utilization,
        source=source,
    )


def analyze_networks(device: Device) -> NetworkAnalysis:
    analysis = NetworkAnalysis()
    seen_networks: dict[str, str] = {}  # cidr -> source, for overlap/duplicate detection
    parsed_nets: list[tuple[ipaddress.IPv4Network, str]] = []

    for iface in device.interfaces:
        for ipv4 in iface.ipv4:
            net = _safe_network(ipv4.address, ipv4.prefix_length)
            if net is None:
                analysis.issues.append(
                    NetworkIssue(
                        severity="HIGH",
                        rule_id="NET-001",
                        category=Category.AVAILABILITY,
                        title="Invalid IPv4 address",
                        description=(
                            f"{ipv4.address}/{ipv4.prefix_length} on {iface.name} is not a "
                            "valid host/prefix combination."
                        ),
                        recommendation="Correct the address or prefix length - this interface cannot pass traffic as configured.",
                        subject=iface.name,
                    )
                )
                continue

            # host bit check: is the configured address actually a host
            # address within its own network (not the network or broadcast id)?
            host_ip = ipaddress.IPv4Address(ipv4.address)
            if ipv4.prefix_length < 31 and host_ip in (net.network_address, net.broadcast_address):
                analysis.issues.append(
                    NetworkIssue(
                        severity="HIGH",
                        rule_id="NET-002",
                        category=Category.AVAILABILITY,
                        title="Interface address is a network/broadcast address",
                        description=(
                            f"{iface.name} is configured with {ipv4.address}/{ipv4.prefix_length}, "
                            "which is the network or broadcast address of that subnet, not a "
                            "usable host address."
                        ),
                        recommendation="Assign a valid host address from within this subnet, not the network or broadcast address.",
                        subject=iface.name,
                    )
                )

            summary = summarize_network(
                ipv4.address, ipv4.prefix_length, ipv4.address, f"interface {iface.name}"
            )
            if summary:
                analysis.networks.append(summary)

            cidr = str(net)
            existing_source = seen_networks.get(cidr)
            if existing_source and existing_source != f"interface {iface.name}":
                analysis.issues.append(
                    NetworkIssue(
                        severity="HIGH",
                        rule_id="NET-003",
                        category=Category.NETWORKING,
                        title="Duplicate network configured on multiple interfaces",
                        description=(
                            f"{cidr} is configured both on {existing_source} and on interface "
                            f"{iface.name}."
                        ),
                        recommendation="Give each interface its own subnet - the same network on two interfaces causes ARP and routing confusion.",
                        subject=iface.name,
                    )
                )
            seen_networks[cidr] = f"interface {iface.name}"

            for other_net, other_source in parsed_nets:
                if other_source == f"interface {iface.name}":
                    continue
                if net.overlaps(other_net) and net != other_net:
                    analysis.issues.append(
                        NetworkIssue(
                            severity="HIGH",
                            rule_id="NET-004",
                            category=Category.NETWORKING,
                            title="Overlapping networks",
                            description=(
                                f"{net} on interface {iface.name} overlaps with {other_net} "
                                f"configured on {other_source}."
                            ),
                            recommendation="Re-address one of the two subnets so they no longer overlap.",
                            subject=iface.name,
                        )
                    )
            parsed_nets.append((net, f"interface {iface.name}"))

            # unnecessarily huge subnet on what looks like a point-to-point/WAN link
            if ipv4.prefix_length <= 23 and _looks_like_wan(iface.name, iface.description):
                analysis.issues.append(
                    NetworkIssue(
                        severity="LOW",
                        rule_id="NET-005",
                        category=Category.BEST_PRACTICES,
                        title="Unusually large subnet on a WAN-looking interface",
                        description=(
                            f"{iface.name} ({net}) has a /{ipv4.prefix_length} prefix, which is "
                            "large for what looks like a WAN/uplink interface. Confirm this is "
                            "intentional."
                        ),
                        recommendation="Point-to-point/WAN links are typically /30 or /31 - confirm this wide a subnet is intentional.",
                        subject=iface.name,
                    )
                )

    for route in device.routing.static_routes:
        net = _safe_network(route.network, route.prefix_length)
        if net is None:
            analysis.issues.append(
                NetworkIssue(
                    severity="MEDIUM",
                    rule_id="NET-006",
                    category=Category.ROUTING,
                    title="Malformed static route",
                    description=f"Static route {route.network}/{route.prefix_length} is not a valid network.",
                    recommendation="Correct the network/prefix on this static route.",
                    subject="routing",
                )
            )
            continue
        if route.next_hop:
            try:
                next_hop_ip = ipaddress.IPv4Address(route.next_hop)
            except ValueError:
                next_hop_ip = None
            if next_hop_ip is not None:
                reachable = any(
                    _safe_network(ipv4.address, ipv4.prefix_length)
                    and next_hop_ip in _safe_network(ipv4.address, ipv4.prefix_length)  # type: ignore[operator]
                    for iface in device.interfaces
                    for ipv4 in iface.ipv4
                )
                if not reachable and route.network != "0.0.0.0":
                    analysis.issues.append(
                        NetworkIssue(
                            severity="MEDIUM",
                            rule_id="NET-007",
                            category=Category.ROUTING,
                            title="Static route next-hop not directly connected",
                            description=(
                                f"Next-hop {route.next_hop} for route {net} is not within any "
                                "locally configured interface subnet. Verify reachability."
                            ),
                            recommendation="Confirm the next-hop is actually reachable - a route to an unreachable next-hop is a route to nowhere.",
                            subject="routing",
                        )
                    )

    for pool in device.dhcp_pools:
        if pool.network is None or pool.prefix_length is None:
            continue
        pool_net = _safe_network(pool.network, pool.prefix_length)
        if pool_net is None:
            continue
        if pool.gateway:
            try:
                gw_ip = ipaddress.IPv4Address(pool.gateway)
                if gw_ip not in pool_net:
                    analysis.issues.append(
                        NetworkIssue(
                            severity="HIGH",
                            rule_id="NET-008",
                            category=Category.AVAILABILITY,
                            title="DHCP gateway outside configured network",
                            description=(
                                f"Gateway {pool.gateway} does not belong to configured network "
                                f"{pool_net} in DHCP pool '{pool.name}'."
                            ),
                            recommendation="Set the gateway to an address inside the pool's own network, or fix the network/prefix.",
                            subject=pool.name,
                        )
                    )
            except ValueError:
                pass
        if pool.range_start and pool.range_end:
            try:
                start_ip = ipaddress.IPv4Address(pool.range_start)
                end_ip = ipaddress.IPv4Address(pool.range_end)
                if start_ip not in pool_net or end_ip not in pool_net:
                    analysis.issues.append(
                        NetworkIssue(
                            severity="HIGH",
                            rule_id="NET-009",
                            category=Category.AVAILABILITY,
                            title="DHCP range outside configured network",
                            description=(
                                f"DHCP range {pool.range_start}-{pool.range_end} in pool "
                                f"'{pool.name}' falls outside network {pool_net}."
                            ),
                            recommendation="Set the DHCP range to fall entirely within the pool's own network.",
                            subject=pool.name,
                        )
                    )
                elif int(end_ip) < int(start_ip):
                    analysis.issues.append(
                        NetworkIssue(
                            severity="MEDIUM",
                            rule_id="NET-010",
                            category=Category.AVAILABILITY,
                            title="DHCP range start after end",
                            description=f"DHCP pool '{pool.name}' has a range end before its start.",
                            recommendation="Swap the range boundaries so the start address comes before the end address.",
                            subject=pool.name,
                        )
                    )
            except ValueError:
                pass

    known_networks: list[ipaddress.IPv4Network] = [net for net, _source in parsed_nets]
    for route in device.routing.static_routes:
        net = _safe_network(route.network, route.prefix_length)
        if net is not None:
            known_networks.append(net)
    for pool in device.dhcp_pools:
        if pool.network is not None and pool.prefix_length is not None:
            net = _safe_network(pool.network, pool.prefix_length)
            if net is not None:
                known_networks.append(net)

    dns_candidates: list[tuple[str, str]] = [(dns, "global DNS configuration") for dns in device.dns_servers]
    dns_candidates += [(dns, f"DHCP pool '{pool.name}'") for pool in device.dhcp_pools for dns in pool.dns_servers]
    seen_dns: set[str] = set()
    for dns, origin in dns_candidates:
        if dns in seen_dns:
            continue
        seen_dns.add(dns)
        try:
            dns_ip = ipaddress.IPv4Address(dns)
        except ValueError:
            continue
        # Only private-range addresses are checked: a public resolver (8.8.8.8,
        # 1.1.1.1, ...) is expected to be reachable via the default route, so
        # it never has to appear in a locally-known subnet to be legitimate.
        if not dns_ip.is_private or dns_ip.is_loopback or dns_ip.is_link_local:
            continue
        if not any(dns_ip in net for net in known_networks):
            analysis.issues.append(
                NetworkIssue(
                    severity="MEDIUM",
                    rule_id="NET-011",
                    category=Category.AVAILABILITY,
                    title="DNS server is not inside any known network",
                    description=(
                        f"{origin} hands out DNS server {dns}, but that address is a private "
                        "address that doesn't fall inside any subnet configured on this device's "
                        "interfaces, static routes, or DHCP pools - clients will likely be unable "
                        "to reach it."
                    ),
                    recommendation="Point clients at a DNS server on a subnet this device can actually reach, or double-check the address for a typo.",
                    subject=origin,
                )
            )

    if device.routing.default_gateway:
        try:
            default_gw_ip: ipaddress.IPv4Address | None = ipaddress.IPv4Address(device.routing.default_gateway)
        except ValueError:
            default_gw_ip = None
        if default_gw_ip is not None and not any(default_gw_ip in net for net, _source in parsed_nets):
            analysis.issues.append(
                NetworkIssue(
                    severity="HIGH",
                    rule_id="NET-012",
                    category=Category.AVAILABILITY,
                    title="Default gateway is not directly reachable",
                    description=(
                        f"The configured default gateway {device.routing.default_gateway} is not "
                        "within any locally configured interface subnet - this device cannot "
                        "actually reach it at Layer 2/3."
                    ),
                    recommendation="Point the default gateway at an address on a directly connected subnet.",
                    subject="routing",
                )
            )

    return analysis


def network_findings(device: Device) -> list[Finding]:
    """Bridge `analyze_networks()` cross-field consistency checks into the
    same `Finding` shape the rule engine produces, so they show up
    alongside every other finding without the UI/health-score/export code
    needing to know these came from a different analyzer."""
    return [
        Finding(
            rule_id=issue.rule_id,
            severity=Severity(issue.severity),
            vendor="all",
            category=issue.category,
            title=issue.title,
            description=issue.description,
            recommendation=issue.recommendation,
            subject=issue.subject,
        )
        for issue in analyze_networks(device).issues
    ]


def _looks_like_wan(name: str, description: str | None) -> bool:
    haystack = f"{name} {description or ''}".lower()
    return any(kw in haystack for kw in ("wan", "uplink", "internet", "isp"))
