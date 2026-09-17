from __future__ import annotations

import re

from app.models.device import Vendor
from app.parsers.base import ConfigParser, ParseResult
from app.parsers.cisco.common import parse_cisco_config

_IOS_XE_MARKERS = re.compile(
    r"boot-start-marker|boot-end-marker|IOS-XE|IOS XE Software|license boot level|call-home",
    re.IGNORECASE,
)
_GENERIC_CISCO_MARKERS = re.compile(
    r"^hostname |^interface (GigabitEthernet|FastEthernet|Ethernet|Serial|Loopback)|"
    r"^enable secret|^ip classless|^line con 0",
    re.MULTILINE,
)


class CiscoIOSParser(ConfigParser):
    vendor = Vendor.CISCO_IOS
    platform_label = "Cisco IOS"

    def parse(self, raw_text: str) -> ParseResult:
        return parse_cisco_config(raw_text, self.vendor, self.platform_label)

    @classmethod
    def detection_score(cls, raw_text: str) -> float:
        if not _GENERIC_CISCO_MARKERS.search(raw_text):
            return 0.0
        score = 0.55
        if re.search(r"^!\s*$", raw_text, re.MULTILINE):
            score += 0.15
        if re.search(r"^version \d+\.\d+", raw_text, re.MULTILINE):
            score += 0.1
        # IOS-XE-specific markers make plain "IOS" less likely
        if _IOS_XE_MARKERS.search(raw_text):
            score -= 0.35
        return max(0.0, min(score, 0.9))
