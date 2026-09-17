"""Secret / sensitive data sanitization.

Design goals (see README "Security & privacy"):
  * Nothing ever leaves the machine this app runs on - sanitization runs
    entirely in-process, no network calls.
  * Masking never destroys structure: `<REDACTED>` replaces exactly the
    secret token, the rest of the line (and the file) is untouched, so the
    sanitized config is still valid to read and reason about.
  * "Reveal" is not "crack". We only ever show a value that was already
    plaintext in the uploaded file, or that is recoverable via a documented,
    deterministic, reversible cipher (Cisco type 7). Genuine one-way hashes
    (type 5/8/9, and anything unrecognised) are reported as present but are
    never guessed at.
"""

from __future__ import annotations

import ipaddress
import re

from app.models.device import Vendor
from app.models.sensitive import (
    Reversibility,
    SanitizationSummary,
    SensitiveCategory,
    SensitiveValue,
)
from app.sanitization.cisco_patterns import find_cisco_sensitive_values
from app.sanitization.mikrotik_patterns import find_mikrotik_sensitive_values

_IPV4_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
_HOSTNAME_LINE_RE = {
    Vendor.CISCO_IOS: re.compile(r"^\s*hostname\s+(\S+)"),
    Vendor.CISCO_IOS_XE: re.compile(r"^\s*hostname\s+(\S+)"),
    Vendor.MIKROTIK_ROUTEROS: re.compile(r"/system identity set name=(\S+)"),
}


class SanitizationResult:
    def __init__(
        self,
        original_text: str,
        sanitized_text: str,
        anonymized_text: str,
        values: list[SensitiveValue],
        summary: SanitizationSummary,
    ) -> None:
        self.original_text = original_text
        self.sanitized_text = sanitized_text
        self.anonymized_text = anonymized_text
        self.values = values
        self.summary = summary

    def revealed_text(self) -> str:
        """Original text with credentials shown, but device identifiers and
        public IPs still masked - the "show passwords" working view."""
        return _apply_replacements(self.original_text, self.values, reveal_credentials=True)


def _find_public_ips(raw_text: str, lines: list[str]) -> list[SensitiveValue]:
    findings: list[SensitiveValue] = []
    counter = 0
    for line_no, line in enumerate(lines, start=1):
        for match in _IPV4_RE.finditer(line):
            candidate = match.group(1)
            try:
                addr = ipaddress.IPv4Address(candidate)
            except ValueError:
                continue
            if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast:
                continue
            # Skip obvious subnet masks like 255.255.255.0 appearing next to
            # an "ip address" line - those aren't addresses of a host/device.
            if candidate.startswith("255.") or candidate == "0.0.0.0":
                continue
            counter += 1
            findings.append(
                SensitiveValue(
                    id=f"pubip-{counter}",
                    category=SensitiveCategory.PUBLIC_IP,
                    secret_type="public IPv4",
                    reversibility=Reversibility.NOT_APPLICABLE,
                    line_number=line_no,
                    masked_value=f"<PUBLIC_IP_{counter}>",
                    revealed_value=candidate,
                    context="public IP address",
                    span_start=match.start(1),
                    span_end=match.end(1),
                )
            )
    return findings


def _apply_replacements(
    raw_text: str, values: list[SensitiveValue], reveal_credentials: bool = False
) -> str:
    lines = raw_text.splitlines()
    by_line: dict[int, list[SensitiveValue]] = {}
    for v in values:
        if v.line_number is None or v.span_start is None or v.span_end is None:
            continue
        by_line.setdefault(v.line_number, []).append(v)

    for line_no, items in by_line.items():
        line = lines[line_no - 1]
        # replace right-to-left so earlier spans stay valid
        for v in sorted(items, key=lambda x: x.span_start or 0, reverse=True):
            replacement = (
                v.revealed_value or v.masked_value
                if reveal_credentials and v.category == SensitiveCategory.CREDENTIAL
                else v.masked_value
            )
            line = line[: v.span_start] + replacement + line[v.span_end :]
        lines[line_no - 1] = line
    return "\n".join(lines)


def sanitize(raw_text: str, vendor: Vendor) -> SanitizationResult:
    lines = raw_text.splitlines()

    if vendor in (Vendor.CISCO_IOS, Vendor.CISCO_IOS_XE):
        credential_and_device = find_cisco_sensitive_values(raw_text)
    elif vendor == Vendor.MIKROTIK_ROUTEROS:
        credential_and_device = find_mikrotik_sensitive_values(raw_text)
    else:
        credential_and_device = []

    public_ips = _find_public_ips(raw_text, lines)

    all_values = credential_and_device + public_ips

    # Sanitized mode: mask credentials + device identifiers only, keep all IPs.
    sanitized_targets = [
        v
        for v in all_values
        if v.category in (SensitiveCategory.CREDENTIAL, SensitiveCategory.DEVICE_IDENTIFIER)
    ]
    sanitized_text = _apply_replacements(raw_text, sanitized_targets)

    # Fully anonymized mode: additionally mask public IPs and the hostname.
    anonymized_targets = list(all_values)
    anonymized_text = _apply_replacements(raw_text, anonymized_targets)
    hostname_re = _HOSTNAME_LINE_RE.get(vendor)
    if hostname_re:
        anon_lines = anonymized_text.splitlines()
        for i, line in enumerate(anon_lines):
            m = hostname_re.match(line)
            if m:
                anon_lines[i] = line[: m.start(1)] + "ANON-HOST" + line[m.end(1) :]
        anonymized_text = "\n".join(anon_lines)

    credentials = [v for v in all_values if v.category == SensitiveCategory.CREDENTIAL]
    device_ids = [v for v in all_values if v.category == SensitiveCategory.DEVICE_IDENTIFIER]
    pub_ips = [v for v in all_values if v.category == SensitiveCategory.PUBLIC_IP]
    reversible = [
        v
        for v in credentials
        if v.reversibility in (Reversibility.PLAINTEXT, Reversibility.REVERSIBLE)
    ]
    hash_only = [v for v in credentials if v.reversibility == Reversibility.ONE_WAY_HASH]

    summary = SanitizationSummary(
        total=len(all_values),
        credentials=len(credentials),
        device_identifiers=len(device_ids),
        public_ips=len(pub_ips),
        reversible_count=len(reversible),
        hash_only_count=len(hash_only),
    )

    return SanitizationResult(
        original_text=raw_text,
        sanitized_text=sanitized_text,
        anonymized_text=anonymized_text,
        values=all_values,
        summary=summary,
    )
