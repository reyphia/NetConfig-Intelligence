"""In-memory local-only workflows built on the vendor-neutral core."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from uuid import uuid4

from app.analyzers.health_score import HealthScore, compute_health_score
from app.models.device import Device, IPv4Interface, Vendor
from app.parsers.base import detect_vendor, get_parser
from app.renderers.cisco import CiscoIOSRenderer, CiscoIOSXERenderer
from app.renderers.mikrotik import MikroTikRouterOSRenderer
from app.rules.engine import get_rule_engine
from app.sanitization.sanitizer import SanitizationResult, sanitize


@dataclass
class AnalysisSession:
    id: str
    device: Device
    vendor: Vendor
    sanitization: SanitizationResult
    findings: list
    health: HealthScore
    original_rendered_text: str
    rendered_text: str | None = None


_sessions: dict[str, AnalysisSession] = {}


def analyze(raw_text: str, selected_vendor: str = "auto") -> AnalysisSession:
    if not raw_text.strip():
        raise ValueError("Upload a configuration file or paste configuration text.")
    detection = detect_vendor(raw_text)
    vendor = detection.vendor if selected_vendor == "auto" else Vendor(selected_vendor)
    if vendor is Vendor.UNKNOWN:
        raise ValueError("Could not identify the vendor. Select Cisco IOS, IOS-XE, or MikroTik manually.")
    parsed = get_parser(vendor).parse(raw_text)
    findings = get_rule_engine().run_all(parsed.device, raw_text)
    session = AnalysisSession(
        id=uuid4().hex,
        device=parsed.device,
        vendor=vendor,
        sanitization=sanitize(raw_text, vendor),
        findings=findings,
        health=compute_health_score(findings),
        # Rendered once, right after parsing, before any edit can mutate
        # `parsed.device` in place - this is the diff baseline. Comparing
        # like-for-like (renderer output vs renderer output) means the diff
        # only ever shows the actual edit, not renderer/raw-text formatting
        # differences (comment markers, `!` delimiters, line ordering, etc).
        original_rendered_text=render_device(parsed.device),
    )
    _sessions[session.id] = session
    return session


def get_session(session_id: str) -> AnalysisSession:
    try:
        return _sessions[session_id]
    except KeyError as exc:
        raise KeyError("This local analysis is no longer available. Analyze the file again.") from exc


def update_interface(session: AnalysisSession, name: str, address: str, prefix_length: int) -> AnalysisSession:
    ipaddress.IPv4Interface(f"{address}/{prefix_length}")
    iface = session.device.get_interface(name)
    if iface is None:
        raise ValueError(f"Interface '{name}' was not found.")
    if iface.ipv4:
        iface.ipv4[0] = IPv4Interface(address=address, prefix_length=prefix_length)
    else:
        iface.ipv4.append(IPv4Interface(address=address, prefix_length=prefix_length))
    session.rendered_text = render_device(session.device)
    session.findings = get_rule_engine().run_all(session.device, session.rendered_text)
    session.health = compute_health_score(session.findings)
    return session


def get_renderer(vendor: Vendor) -> CiscoIOSRenderer | CiscoIOSXERenderer | MikroTikRouterOSRenderer:
    if vendor == Vendor.CISCO_IOS:
        return CiscoIOSRenderer()
    if vendor == Vendor.CISCO_IOS_XE:
        return CiscoIOSXERenderer()
    if vendor == Vendor.MIKROTIK_ROUTEROS:
        return MikroTikRouterOSRenderer()
    raise ValueError(f"No renderer registered for {vendor.value}.")


def render_device(device: Device) -> str:
    return get_renderer(device.vendor).render(device)
