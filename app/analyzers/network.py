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
                        title="Invalid IPv4 address",
                        description=(
                            f"{ipv4.address}/{ipv4.prefix_length} on {iface.name} is not a "
                            "valid host/prefix combination."
                        ),
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
                        title="Interface address is a network/broadcast address",
                        description=(
                            f"{iface.name} is configured with {ipv4.address}/{ipv4.prefix_length}, "
                            "which is the network or broadcast address of that subnet, not a "
                            "usable host address."
                        ),
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
                        title="Duplicate network configured on multiple interfaces",
                        description=(
                            f"{cidr} is configured both on {existing_source} and on interface "
                            f"{iface.name}."
                        ),
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
                            title="Overlapping networks",
                            description=(
                                f"{net} on interface {iface.name} overlaps with {other_net} "
                                f"configured on {other_source}."
                            ),
                            subject=iface.name,
                        )
                    )
            parsed_nets.append((net, f"interface {iface.name}"))

            # unnecessarily huge subnet on what looks like a point-to-point/WAN link
            if ipv4.prefix_length <= 23 and _looks_like_wan(iface.name, iface.description):
                analysis.issues.append(
                    NetworkIssue(
                        severity="LOW",
                        title="Unusually large subnet on a WAN-looking interface",
                        description=(
                            f"{iface.name} ({net}) has a /{ipv4.prefix_length} prefix, which is "
                            "large for what looks like a WAN/uplink interface. Confirm this is "
                            "intentional."
                        ),
                        subject=iface.name,
                    )
                )

    for route in device.routing.static_routes:
        net = _safe_network(route.network, route.prefix_length)
        if net is None:
            analysis.issues.append(
                NetworkIssue(
                    severity="MEDIUM",
                    title="Malformed static route",
                    description=f"Static route {route.network}/{route.prefix_length} is not a valid network.",
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
                            title="Static route next-hop not directly connected",
                            description=(
                                f"Next-hop {route.next_hop} for route {net} is not within any "
                                "locally configured interface subnet. Verify reachability."
                            ),
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
                            title="DHCP gateway outside configured network",
                            description=(
                                f"Gateway {pool.gateway} does not belong to configured network "
                                f"{pool_net} in DHCP pool '{pool.name}'."
                            ),
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
                            title="DHCP range outside configured network",
                            description=(
                                f"DHCP range {pool.range_start}-{pool.range_end} in pool "
                                f"'{pool.name}' falls outside network {pool_net}."
                            ),
                            subject=pool.name,
                        )
                    )
                elif int(end_ip) < int(start_ip):
                    analysis.issues.append(
                        NetworkIssue(
                            severity="MEDIUM",
                            title="DHCP range start after end",
                            description=f"DHCP pool '{pool.name}' has a range end before its start.",
                            subject=pool.name,
                        )
                    )
            except ValueError:
                pass

    return analysis


def _looks_like_wan(name: str, description: str | None) -> bool:
    haystack = f"{name} {description or ''}".lower()
    return any(kw in haystack for kw in ("wan", "uplink", "internet", "isp"))
