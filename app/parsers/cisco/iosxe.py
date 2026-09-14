from __future__ import annotations

import re

from app.models.device import Vendor
from app.parsers.base import ConfigParser, ParseResult
from app.parsers.cisco.common import parse_cisco_config

_IOS_XE_MARKERS = re.compile(
    r"boot-start-marker|boot-end-marker|IOS-XE|IOS XE Software|license boot level|"
    r"call-home|platform \S|crypto pki certificate|subscriber-policy",
    re.IGNORECASE,
)
_GENERIC_CISCO_MARKERS = re.compile(
    r"^hostname |^interface (GigabitEthernet|FastEthernet|Ethernet|Serial|Loopback|Port-channel)|"
    r"^enable secret|^ip classless|^line con 0",
    re.MULTILINE,
)


class CiscoIOSXEParser(ConfigParser):
    vendor = Vendor.CISCO_IOS_XE
    platform_label = "Cisco IOS-XE"

    def parse(self, raw_text: str) -> ParseResult:
        return parse_cisco_config(raw_text, self.vendor, self.platform_label)

    @classmethod
    def detection_score(cls, raw_text: str) -> float:
        if not _GENERIC_CISCO_MARKERS.search(raw_text):
            return 0.0
        score = 0.4
        marker_hits = len(_IOS_XE_MARKERS.findall(raw_text))
        score += min(marker_hits * 0.15, 0.5)
        return max(0.0, min(score, 0.97))
