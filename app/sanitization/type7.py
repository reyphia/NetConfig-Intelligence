"""Cisco "type 7" password cipher.

Cisco IOS `service password-encryption` applies a simple, publicly
documented XOR cipher (sometimes called the "Vigenere" cipher) using a
fixed, well-known key table. It was never designed to resist recovery -
Cisco's own documentation describes it as obfuscation, not encryption.

Decoding a type 7 value that appears in a configuration you already own is a
standard, legitimate network engineering task (equivalent to base64-decoding
a value) and is implemented in essentially every network automation toolkit.
It is NOT password cracking: no guessing or brute force is involved, the
plaintext is deterministically recovered.

This module does not attempt anything of the sort for type 5 (MD5-crypt),
type 8 (PBKDF2-SHA256) or type 9 (scrypt) secrets, which are genuine one-way
hashes - see sanitizer.py, those are only ever reported as "hash present".
"""

from __future__ import annotations

# Cisco's fixed XOR key stream used for type 7 passwords.
_XLAT = [
    0x64, 0x73, 0x66, 0x64, 0x3B, 0x6B, 0x66, 0x6F, 0x41, 0x2C, 0x2E, 0x69,
    0x79, 0x65, 0x77, 0x72, 0x6B, 0x6C, 0x64, 0x4A, 0x4B, 0x44, 0x48, 0x53,
    0x55, 0x42, 0x73, 0x67, 0x76, 0x63, 0x61, 0x36, 0x39, 0x38, 0x33, 0x34,
    0x6E, 0x63, 0x78, 0x76, 0x39, 0x38, 0x37, 0x33, 0x32, 0x35, 0x34, 0x6B,
    0x3B, 0x66, 0x67, 0x38, 0x37,
]


class Type7DecodeError(ValueError):
    pass


def is_valid_type7(value: str) -> bool:
    """A type 7 string is a 2-digit seed followed by an even number of hex digits."""
    value = value.strip()
    if len(value) < 4 or not value[:2].isdigit():
        return False
    body = value[2:]
    if len(body) % 2 != 0:
        return False
    try:
        int(body, 16)
    except ValueError:
        return False
    seed = int(value[:2])
    return 0 <= seed <= 52


def decode_type7(value: str) -> str:
    """Decode a Cisco type 7 password to plaintext.

    Raises Type7DecodeError if the value is not a well-formed type 7 string.
    """
    value = value.strip()
    if not is_valid_type7(value):
        raise Type7DecodeError(f"not a well-formed type 7 value: {value!r}")

    seed = int(value[:2])
    hex_body = value[2:]
    result = bytearray()
    key_index = seed
    for i in range(0, len(hex_body), 2):
        byte = int(hex_body[i : i + 2], 16)
        key_index_mod = key_index % len(_XLAT)
        result.append(byte ^ _XLAT[key_index_mod])
        key_index += 1
    try:
        return result.decode("utf-8")
    except UnicodeDecodeError as exc:  # pragma: no cover - malformed input
        raise Type7DecodeError("decoded bytes are not valid text") from exc


def encode_type7(plaintext: str, seed: int = 0) -> str:
    """Encode plaintext into a type 7 string (used only by demo fixtures/tests)."""
    if not 0 <= seed <= 52:
        raise ValueError("seed must be between 0 and 52")
    key_index = seed
    out = bytearray()
    for ch in plaintext.encode("utf-8"):
        key_index_mod = key_index % len(_XLAT)
        out.append(ch ^ _XLAT[key_index_mod])
        key_index += 1
    return f"{seed:02d}" + out.hex()
