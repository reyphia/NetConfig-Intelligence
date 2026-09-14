from __future__ import annotations

import re

from app.models.sensitive import Reversibility, SensitiveCategory, SensitiveValue
from app.sanitization.type7 import decode_type7, is_valid_type7

# (regex, group index of the secret token, human label, classifier)
# Classifier decides SecretType/Reversibility from the captured "type digit"
# (or None if the line has no explicit type digit, i.e. plaintext).

_MAC_RE = re.compile(r"\b[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\b")

_CREDENTIAL_LINE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^\s*enable secret (?:level \d+ )?(\d+ )?(\S+)\s*$"), "enable secret"),
    (re.compile(r"^\s*enable password (?:level \d+ )?(\d+ )?(\S+)\s*$"), "enable password"),
    (
        re.compile(
            r"^\s*username (\S+)(?:.*?)\s(?:secret|password) (\d+ )?(\S+)\s*$"
        ),
        "username secret/password",
    ),
    (re.compile(r"^\s*password (\d+ )?(\S+)\s*$"), "line password"),
    (re.compile(r"^\s*snmp-server community (\S+)"), "SNMP community"),
    (re.compile(r"^\s*tacacs-server key (\d+ )?(\S+)\s*$"), "TACACS+ key"),
    (re.compile(r"^\s*radius-server key (\d+ )?(\S+)\s*$"), "RADIUS key"),
    (re.compile(r"^\s*ntp authentication-key \d+ md5 (\d+ )?(\S+)\s*$"), "NTP MD5 key"),
    (
        re.compile(r"^\s*ip ospf message-digest-key \d+ md5 (\d+ )?(\S+)\s*$"),
        "OSPF MD5 key",
    ),
    (re.compile(r"^\s*ip ospf authentication-key (\d+ )?(\S+)\s*$"), "OSPF auth key"),
    (re.compile(r"^\s*standby \d+ authentication (?:md5 key-string )?(\d+ )?(\S+)\s*$"), "HSRP auth key"),
]


def _classify(type_digit: str | None, token: str) -> tuple[str, Reversibility, str | None]:
    """Return (secret_type_label, reversibility, revealed_value)."""
    digit = (type_digit or "").strip()
    if digit == "7":
        if is_valid_type7(token):
            try:
                return "Cisco type 7", Reversibility.REVERSIBLE, decode_type7(token)
            except (IndexError, ValueError):
                return "Cisco type 7 (malformed)", Reversibility.ONE_WAY_HASH, None
        return "Cisco type 7 (malformed)", Reversibility.ONE_WAY_HASH, None
    if digit == "5":
        return "MD5-crypt (type 5)", Reversibility.ONE_WAY_HASH, None
    if digit == "8":
        return "PBKDF2-SHA256 (type 8)", Reversibility.ONE_WAY_HASH, None
    if digit == "9":
        return "scrypt (type 9)", Reversibility.ONE_WAY_HASH, None
    if digit == "0" or digit == "":
        # type 0 (or no type digit at all) means "stored in clear text"
        return "plaintext", Reversibility.PLAINTEXT, token
    return "unknown", Reversibility.ONE_WAY_HASH, None


def find_cisco_sensitive_values(raw_text: str) -> list[SensitiveValue]:
    findings: list[SensitiveValue] = []
    counter = 0
    lines = raw_text.splitlines()

    for line_no, line in enumerate(lines, start=1):
        for pattern, label in _CREDENTIAL_LINE_PATTERNS:
            match = pattern.match(line)
            if not match:
                continue
            groups = match.groups()
            # last group is always the secret token; the one before it (if
            # present) is the type digit for most patterns.
            token = groups[-1]
            type_digit = groups[-2] if len(groups) >= 2 else None
            if type_digit and not type_digit.strip().isdigit():
                type_digit = None
            secret_label, reversibility, revealed = _classify(type_digit, token)
            counter += 1
            findings.append(
                SensitiveValue(
                    id=f"cred-{counter}",
                    category=SensitiveCategory.CREDENTIAL,
                    secret_type=secret_label,
                    reversibility=reversibility,
                    line_number=line_no,
                    masked_value=_mask_token(token),
                    revealed_value=revealed,
                    context=label,
                    span_start=match.start(len(groups)),
                    span_end=match.end(len(groups)),
                )
            )
            break  # a line only matches one credential pattern

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


def _mask_token(token: str) -> str:
    return "<REDACTED>"
