from __future__ import annotations

from enum import Enum

from pydantic import BaseModel


class SensitiveCategory(str, Enum):
    CREDENTIAL = "credential"  # passwords, secrets, keys, SNMP communities
    DEVICE_IDENTIFIER = "device_identifier"  # serials, MACs, hostnames (opt-in)
    PUBLIC_IP = "public_ip"


class Reversibility(str, Enum):
    # The value can be shown exactly as it controls device access, because it
    # was already stored in clear text in the uploaded file.
    PLAINTEXT = "plaintext"
    # The value is recoverable via a known, publicly documented reversible
    # cipher (Cisco type 7). Not a "crack" - a decode.
    REVERSIBLE = "reversible"
    # The value is a one-way hash/digest. NetConfig Intelligence never
    # attempts to crack or brute-force these; only their presence is shown.
    ONE_WAY_HASH = "one_way_hash"
    # Not a credential at all (IP, MAC, serial) - "reveal" just means
    # "don't mask it", there was never anything to decode.
    NOT_APPLICABLE = "not_applicable"


class SensitiveValue(BaseModel):
    id: str
    category: SensitiveCategory
    secret_type: str  # human label, e.g. "Cisco type 7", "MD5-crypt (type 5)"
    reversibility: Reversibility
    line_number: int | None = None
    masked_value: str  # what is shown by default, e.g. <SECRET_3>
    revealed_value: str | None = None  # populated only when recoverable
    context: str | None = None  # short surrounding label, e.g. "username admin"
    span_start: int | None = None  # character offset of the token within its line
    span_end: int | None = None


class SanitizationSummary(BaseModel):
    total: int
    credentials: int
    device_identifiers: int
    public_ips: int
    reversible_count: int  # how many of the credentials can actually be revealed
    hash_only_count: int  # how many are one-way hashes and can never be shown
