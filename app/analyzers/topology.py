"""Renders a single device's interfaces, VLANs, ACLs, and routing as an
inline SVG diagram.

This is deliberately a single-device view (multi-device topology - drawing
several configs against each other - needs a session model that can hold
more than one device, which is a separate, larger piece of work). What this
still gets you today: a picture of "this box" that answers the questions a
new admin actually has - what's plugged into what, which interfaces are
addressed vs down, which ACLs/VLANs are actually wired up vs dangling, and
whether the routes this device has actually point somewhere reachable.

Colors are emitted as CSS custom properties (`var(--accent)`, etc.) so the
diagram automatically matches the app's theme - it's injected straight into
the page, not rendered as a standalone image.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from xml.sax.saxutils import escape

from app.models.device import Device, Interface

_OK = "var(--accent)"
_BAD = "var(--critical)"
_WARN = "var(--medium)"
_MUTED = "var(--muted)"
_FAINT = "var(--faint)"
_LINE = "var(--line-strong)"
_TEXT = "var(--text)"
_SURFACE = "var(--surface)"
_SURFACE_2 = "var(--surface-2)"
_CYAN = "var(--cyan)"

_CARD_W = 360
_CARD_GAP = 16
_CHIP_H = 20
_CHIP_GAP = 6
_CHIP_CHAR_W = 6.4  # rough monospace-ish width estimate for chip sizing


def _esc(value: object) -> str:
    return escape(str(value))


def _safe_network(address: str, prefix_length: int) -> ipaddress.IPv4Network | None:
    try:
        return ipaddress.IPv4Network(f"{address}/{prefix_length}", strict=False)
    except ValueError:
        return None


def _locally_reachable(address: str | None, device: Device) -> bool | None:
    """True/False if we can tell, None if the address itself doesn't parse."""
    if not address:
        return None
    try:
        ip = ipaddress.IPv4Address(address)
    except ValueError:
        return None
    for iface in device.interfaces:
        for ipv4 in iface.ipv4:
            net = _safe_network(ipv4.address, ipv4.prefix_length)
            if net and ip in net:
                return True
    return False


@dataclass
class _Chip:
    text: str
    color: str = _MUTED
    filled: bool = False


@dataclass
class _CardLayout:
    chip_rows: list[list[_Chip]] = field(default_factory=list)
    height: float = 0.0


def _wrap_chips(chips: list[_Chip], max_width: float) -> list[list[_Chip]]:
    rows: list[list[_Chip]] = []
    current: list[_Chip] = []
    current_w = 0.0
    for chip in chips:
        chip_w = len(chip.text) * _CHIP_CHAR_W + 20
        if current and current_w + chip_w > max_width:
            rows.append(current)
            current, current_w = [], 0.0
        current.append(chip)
        current_w += chip_w + _CHIP_GAP
    if current:
        rows.append(current)
    return rows


def _interface_chips(iface: Interface, acl_names: set[str]) -> list[_Chip]:
    chips: list[_Chip] = []
    if iface.vlan:
        chips.append(_Chip(f"VLAN {iface.vlan}", _CYAN))
    if iface.mode.value == "trunk" and iface.trunk_allowed_vlans:
        shown = ",".join(str(v) for v in iface.trunk_allowed_vlans[:6])
        more = "…" if len(iface.trunk_allowed_vlans) > 6 else ""
        chips.append(_Chip(f"TRUNK {shown}{more}", _CYAN))
    for label, acl_name in (("ACL-IN", iface.inbound_acl), ("ACL-OUT", iface.outbound_acl)):
        if not acl_name:
            continue
        if acl_name in acl_names:
            chips.append(_Chip(f"{label} {acl_name}", _OK))
        else:
            chips.append(_Chip(f"{label} {acl_name} ✕ undefined", _BAD, filled=True))
    return chips


def _interface_card_layout(iface: Interface, acl_names: set[str]) -> _CardLayout:
    chips = _interface_chips(iface, acl_names)
    rows = _wrap_chips(chips, _CARD_W - 28)
    base_height = 62  # title + address line + padding
    chip_area = len(rows) * (_CHIP_H + _CHIP_GAP) if rows else 0
    return _CardLayout(chip_rows=rows, height=base_height + chip_area)


def _status_color(iface: Interface) -> str:
    if not iface.enabled:
        return _BAD
    if iface.ipv4 or iface.ipv6:
        return _OK
    return _FAINT


def _address_text(iface: Interface) -> str:
    if iface.ipv4:
        return ", ".join(f"{a.address}/{a.prefix_length}" for a in iface.ipv4)
    if iface.ipv6:
        return ", ".join(f"{a.address}/{a.prefix_length}" for a in iface.ipv6)
    return "no IPv4/IPv6 address"


def _chip_svg(chip: _Chip, x: float, y: float) -> tuple[str, float]:
    width = len(chip.text) * _CHIP_CHAR_W + 20
    fill = chip.color if chip.filled else "transparent"
    text_color = "var(--accent-ink)" if chip.filled else chip.color
    svg = (
        f'<rect x="{x:.1f}" y="{y:.1f}" width="{width:.1f}" height="{_CHIP_H}" rx="10" '
        f'fill="{fill}" stroke="{chip.color}" stroke-width="1" opacity="{1.0 if chip.filled else 0.9}"/>'
        f'<text x="{x + width / 2:.1f}" y="{y + _CHIP_H / 2 + 4:.1f}" text-anchor="middle" '
        f'font-family="var(--font-mono)" font-size="10.5" font-weight="700" fill="{text_color}">'
        f"{_esc(chip.text)}</text>"
    )
    return svg, width


def render_topology_svg(device: Device) -> str:
    acl_names = {acl.name for acl in device.acls}
    interfaces = device.interfaces

    layouts = [_interface_card_layout(iface, acl_names) for iface in interfaces]
    interfaces_total_h = sum(layout.height for layout in layouts) + _CARD_GAP * max(len(layouts) - 1, 0)

    routes: list[tuple[str, str, bool | None]] = []
    if device.routing.default_gateway:
        routes.append(("default", device.routing.default_gateway, _locally_reachable(device.routing.default_gateway, device)))
    for route in device.routing.static_routes:
        dest = f"{route.network}/{route.prefix_length}"
        if route.next_hop:
            routes.append((dest, route.next_hop, _locally_reachable(route.next_hop, device)))
        elif route.interface:
            routes.append((dest, f"via {route.interface}", None))

    route_row_h = 30
    routes_total_h = len(routes) * route_row_h

    services_lines = _services_summary(device)
    services_h = 34 + len(services_lines) * 18 if services_lines else 0

    device_x, top_margin = 24, 24
    device_w, device_h = 200, 88
    iface_x = device_x + device_w + 130

    # The device+services column and the interface-card column are laid out
    # side by side, top-aligned to the same band, then each centered within
    # whichever of the two is taller - so neither can ever overflow past the
    # bottom of the other. Routing (if any) goes in its own band *below*
    # both, never beside them, so its connectors can't cut across interface
    # cards on the way to the routing rows.
    left_col_h = device_h + (16 + services_h if services_lines else 0)
    band_h = max(interfaces_total_h, left_col_h, 100)

    dev_y = top_margin + (band_h - left_col_h) / 2
    iface_start_y = top_margin + (band_h - interfaces_total_h) / 2
    device_cy = dev_y + device_h / 2

    has_routes = bool(routes)
    routing_gap = 44 if has_routes else 0
    routing_header_h = 24 if has_routes else 0
    height = top_margin + band_h + routing_gap + routing_header_h + routes_total_h + 24
    width = iface_x + _CARD_W + 40

    parts: list[str] = [
        f'<svg viewBox="0 0 {width:.0f} {height:.0f}" xmlns="http://www.w3.org/2000/svg" font-family="var(--font-body)">',
    ]

    # ---- device node ----
    parts.append(
        f'<rect x="{device_x}" y="{dev_y:.1f}" width="{device_w}" height="{device_h}" rx="14" '
        f'fill="{_SURFACE_2}" stroke="{_OK}" stroke-width="1.5"/>'
    )
    parts.append(
        f'<text x="{device_x + device_w / 2}" y="{dev_y + 30:.1f}" text-anchor="middle" '
        f'font-family="var(--font-mono)" font-size="14" font-weight="700" fill="{_TEXT}">'
        f'{_esc(device.hostname or "unnamed-device")}</text>'
    )
    parts.append(
        f'<text x="{device_x + device_w / 2}" y="{dev_y + 52:.1f}" text-anchor="middle" '
        f'font-size="11" fill="{_MUTED}">{_esc(device.vendor.value.replace("_", " "))}</text>'
    )
    parts.append(
        f'<text x="{device_x + device_w / 2}" y="{dev_y + 70:.1f}" text-anchor="middle" '
        f'font-size="10.5" fill="{_FAINT}">{len(interfaces)} interface(s)</text>'
    )

    # ---- services panel, stacked under the device node ----
    left_col_bottom = dev_y + device_h
    if services_lines:
        svc_y = dev_y + device_h + 16
        left_col_bottom = svc_y + services_h
        parts.append(
            f'<rect x="{device_x}" y="{svc_y:.1f}" width="{device_w}" height="{services_h:.1f}" rx="12" '
            f'fill="{_SURFACE}" stroke="{_LINE}"/>'
        )
        parts.append(
            f'<text x="{device_x + 12}" y="{svc_y + 20:.1f}" font-size="10" font-weight="700" '
            f'letter-spacing="0.06em" fill="{_FAINT}">SERVICES</text>'
        )
        for i, (label, color) in enumerate(services_lines):
            ly = svc_y + 38 + i * 18
            parts.append(
                f'<text x="{device_x + 12}" y="{ly:.1f}" font-family="var(--font-mono)" '
                f'font-size="10.5" fill="{color}">{_esc(label)}</text>'
            )

    # ---- interface cards ----
    y_cursor: float = iface_start_y
    for iface, layout in zip(interfaces, layouts):
        card_y = y_cursor
        card_cy = card_y + layout.height / 2
        status = _status_color(iface)

        # connector from device to this card
        mid_x = (device_x + device_w + iface_x) / 2
        parts.append(
            f'<path d="M {device_x + device_w} {device_cy:.1f} C {mid_x:.1f} {device_cy:.1f}, '
            f'{mid_x:.1f} {card_cy:.1f}, {iface_x} {card_cy:.1f}" fill="none" '
            f'stroke="{_LINE}" stroke-width="1.5"/>'
        )

        parts.append(
            f'<rect x="{iface_x}" y="{card_y:.1f}" width="{_CARD_W}" height="{layout.height:.1f}" rx="12" '
            f'fill="{_SURFACE}" stroke="{_LINE}"/>'
        )
        parts.append(f'<circle cx="{iface_x + 16}" cy="{card_y + 20:.1f}" r="4" fill="{status}"/>')
        parts.append(
            f'<text x="{iface_x + 30}" y="{card_y + 24:.1f}" font-family="var(--font-mono)" '
            f'font-size="12.5" font-weight="700" fill="{_TEXT}">{_esc(iface.name)}'
            + (f" — {_esc(iface.description)}" if iface.description else "")
            + "</text>"
        )
        addr_color = _BAD if not iface.enabled else _MUTED
        addr_text = "shut down" if not iface.enabled else _address_text(iface)
        parts.append(
            f'<text x="{iface_x + 16}" y="{card_y + 44:.1f}" font-size="11.5" fill="{addr_color}">'
            f"{_esc(addr_text)}</text>"
        )

        chip_y = card_y + 54
        for row in layout.chip_rows:
            chip_x: float = iface_x + 16
            for chip in row:
                chip_svg, w = _chip_svg(chip, chip_x, chip_y)
                parts.append(chip_svg)
                chip_x += w + _CHIP_GAP
            chip_y += _CHIP_H + _CHIP_GAP

        y_cursor += layout.height + _CARD_GAP

    if not interfaces:
        parts.append(
            f'<text x="{iface_x}" y="{device_cy:.1f}" font-size="12" fill="{_MUTED}">'
            "No interfaces were parsed from this configuration.</text>"
        )

    # ---- routing band, below everything above so its connectors never
    # cross an interface card ----
    if routes:
        routing_top = top_margin + band_h + routing_gap
        trunk_x = device_x + device_w / 2
        parts.append(
            f'<text x="{iface_x}" y="{routing_top - 12:.1f}" font-size="10" font-weight="700" '
            f'letter-spacing="0.06em" fill="{_FAINT}">ROUTING</text>'
        )
        for i, (dest, target, reachable) in enumerate(routes):
            row_cy = routing_top + routing_header_h + i * route_row_h + route_row_h / 2
            mid_y = (left_col_bottom + row_cy) / 2
            parts.append(
                f'<path d="M {trunk_x} {left_col_bottom:.1f} C {trunk_x} {mid_y:.1f}, '
                f'{iface_x} {mid_y:.1f}, {iface_x} {row_cy:.1f}" fill="none" '
                f'stroke="{_LINE}" stroke-width="1" stroke-dasharray="3,3"/>'
            )
            dot_color = _FAINT if reachable is None else (_OK if reachable else _BAD)
            parts.append(f'<circle cx="{iface_x + 6}" cy="{row_cy:.1f}" r="4" fill="{dot_color}"/>')
            parts.append(
                f'<text x="{iface_x + 18}" y="{row_cy + 4:.1f}" font-family="var(--font-mono)" '
                f'font-size="11" fill="{_TEXT}">{_esc(dest)} → {_esc(target)}</text>'
            )

    parts.append("</svg>")
    return "".join(parts)


def _services_summary(device: Device) -> list[tuple[str, str]]:
    lines: list[tuple[str, str]] = []
    if device.nat_rules:
        lines.append((f"NAT: {len(device.nat_rules)} rule(s)", _MUTED))
    if device.dhcp_pools:
        lines.append((f"DHCP: {len(device.dhcp_pools)} pool(s)", _MUTED))
    if device.dns_servers:
        lines.append((f"DNS: {', '.join(device.dns_servers[:3])}", _MUTED))
    for svc in device.management:
        if not svc.enabled:
            continue
        color = _BAD if svc.name.lower() == "telnet" else _OK
        lines.append((f"{svc.name}: enabled", color))
    return lines[:6]
