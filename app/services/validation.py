"""Pre-export validation based on the normalized model."""

from __future__ import annotations

import ipaddress

from app.analyzers.network import analyze_networks
from app.models.device import Device


def validate_device(device: Device) -> list[dict[str, str]]:
    checks = [{"name": "Syntax", "status": "pass", "detail": "Parsed into the normalized model."}]
    for iface in device.interfaces:
        for address in iface.ipv4:
            try:
                ipaddress.IPv4Interface(f"{address.address}/{address.prefix_length}")
            except ValueError:
                checks.append({"name": "IP addressing", "status": "blocking", "detail": f"{iface.name}: invalid {address.address}/{address.prefix_length}."})
    network_issues = analyze_networks(device).issues
    for issue in network_issues:
        checks.append({"name": issue.title, "status": "blocking" if issue.severity in {"CRITICAL", "HIGH"} else "warning", "detail": issue.description})
    if not network_issues:
        checks.append({"name": "Network consistency", "status": "pass", "detail": "No blocking network consistency issue found."})
    if device.unparsed_lines:
        checks.append(
            {
                "name": "Lines outside the normalized model",
                "status": "warning",
                "detail": (
                    f"{len(device.unparsed_lines)} original line(s) (e.g. logging, NTP, or other "
                    "directives NetConfig Intelligence does not yet model) are not represented in "
                    "the normalized model, so they will be dropped from any exported *modified* "
                    "configuration (interface/object editing is not yet exposed in the web UI - "
                    "see Roadmap)."
                ),
            }
        )
    return checks
