from __future__ import annotations

import re

from app.models.sensitive import Reversibility, SensitiveCategory, SensitiveValue

_MAC_RE = re.compile(r"\b[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}\b")

# RouterOS stores these fields in clear text inside the export because the
# device needs the plaintext at runtime (PPP secrets, PSKs, RADIUS/SNMP
# shared secrets, IPsec keys). Unlike Cisco's hashed "secret" fields, there
# is nothing to decode here - the value in the file already *is* the secret,
# which is exactly why NetConfig Intelligence masks it by default.
_KEY_VALUE_RE = re.compile(
    r"\b(password|secret|key|wpa-pre-shared-key|wpa2-pre-shared-key|pre-shared-key)="
    r'(?:"([^"]*)"|(\S+))'
)

_SNMP_COMMUNITY_LINE_RE = re.compile(r"^/snmp community.*?\bname=(\S+)")


def find_mikrotik_sensitive_values(raw_text: str) -> list[SensitiveValue]:
    findings: list[SensitiveValue] = []
    counter = 0
    lines = raw_text.splitlines()

    for line_no, line in enumerate(lines, start=1):
        for match in _KEY_VALUE_RE.finditer(line):
            field_name = match.group(1)
            token = match.group(2) if match.group(2) is not None else match.group(3)
            if not token:
                continue
            counter += 1
            # group(2) is the quoted body, group(3) the unquoted body - find
            # which one matched to compute the right span for substitution.
            token_start, token_end = match.span(2 if match.group(2) is not None else 3)
            findings.append(
                SensitiveValue(
                    id=f"cred-{counter}",
                    category=SensitiveCategory.CREDENTIAL,
                    secret_type="plaintext",
                    reversibility=Reversibility.PLAINTEXT,
                    line_number=line_no,
                    masked_value="<REDACTED>",
                    revealed_value=token,
                    context=field_name,
                    span_start=token_start,
                    span_end=token_end,
                )
            )

        for mac_match in _MAC_RE.finditer(line):
            counter += 1
            token = mac_match.group(0)
            findings.append(
                SensitiveValue(
                    id=f"dev-{counter}",
                    category=SensitiveCategory.DEVICE_IDENTIFIER,
                    secret_type="MAC address",
                    reversibility=Reversibility.NOT_APPLICABLE,
                    line_number=line_no,
                    masked_value="<MAC_REDACTED>",
                    revealed_value=token,
                    context="MAC address",
                    span_start=mac_match.start(),
                    span_end=mac_match.end(),
                )
            )

    return findings
