"""Vendor-plugin parser abstraction.

Adding a new vendor means: implement `ConfigParser`, register it in
`PARSERS` and add detection heuristics to `detect_vendor`. Nothing else in
the application needs to change - analyzers, the editor, diff and replay all
work off the normalized `Device` model.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from app.models.device import Device, Vendor


class ParseWarning:
    def __init__(self, line_number: int, message: str) -> None:
        self.line_number = line_number
        self.message = message


class ParseResult:
    def __init__(self, device: Device, warnings: list[ParseWarning] | None = None) -> None:
        self.device = device
        self.warnings = warnings or []


class ConfigParser(ABC):
    vendor: Vendor
    platform_label: str

    @abstractmethod
    def parse(self, raw_text: str) -> ParseResult:
        """Parse raw configuration text into a normalized Device model."""
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def detection_score(cls, raw_text: str) -> float:
        """Return a confidence score in [0, 1] that raw_text is this vendor/platform."""
        raise NotImplementedError


class VendorDetectionResult:
    def __init__(self, vendor: Vendor, confidence: float, candidates: list[tuple[Vendor, float]]):
        self.vendor = vendor
        self.confidence = confidence
        self.candidates = candidates  # all candidates, sorted desc, for transparency in the UI


def detect_vendor(raw_text: str) -> VendorDetectionResult:
    # Imported lazily to avoid circular imports between base.py and the
    # concrete parser modules that import ConfigParser from here.
    from app.parsers.cisco.ios import CiscoIOSParser
    from app.parsers.cisco.iosxe import CiscoIOSXEParser
    from app.parsers.mikrotik.routeros import MikroTikRouterOSParser

    candidates = [
        (Vendor.CISCO_IOS, CiscoIOSParser.detection_score(raw_text)),
        (Vendor.CISCO_IOS_XE, CiscoIOSXEParser.detection_score(raw_text)),
        (Vendor.MIKROTIK_ROUTEROS, MikroTikRouterOSParser.detection_score(raw_text)),
    ]
    candidates.sort(key=lambda c: c[1], reverse=True)
    best_vendor, best_score = candidates[0]
    if best_score <= 0.0:
        return VendorDetectionResult(Vendor.UNKNOWN, 0.0, candidates)
    return VendorDetectionResult(best_vendor, best_score, candidates)


PARSERS: dict[Vendor, type[ConfigParser]] = {}


def register_parsers() -> None:
    """Populate the PARSERS registry. Called once at import time by __init__."""
    from app.parsers.cisco.ios import CiscoIOSParser
    from app.parsers.cisco.iosxe import CiscoIOSXEParser
    from app.parsers.mikrotik.routeros import MikroTikRouterOSParser

    PARSERS[Vendor.CISCO_IOS] = CiscoIOSParser
    PARSERS[Vendor.CISCO_IOS_XE] = CiscoIOSXEParser
    PARSERS[Vendor.MIKROTIK_ROUTEROS] = MikroTikRouterOSParser


def get_parser(vendor: Vendor) -> ConfigParser:
    if not PARSERS:
        register_parsers()
    parser_cls = PARSERS.get(vendor)
    if parser_cls is None:
        raise ValueError(f"No parser registered for vendor {vendor}")
    return parser_cls()
