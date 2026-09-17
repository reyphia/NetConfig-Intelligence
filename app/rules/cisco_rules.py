from __future__ import annotations

import re

from app.models.device import Device, SecretType, Vendor
from app.models.findings import Category, Severity
from app.rules.engine import Hit, Rule, RuleEngine

_CISCO_VENDORS = (Vendor.CISCO_IOS, Vendor.CISCO_IOS_XE)


def register_all(engine: RuleEngine) -> None:
    for vendor in _CISCO_VENDORS:
        engine.register(_telnet_enabled(vendor))
        engine.register(_http_without_https(vendor))
        engine.register(_ssh_not_configured(vendor))
        engine.register(_weak_password_storage(vendor))
        engine.register(_missing_login_banner(vendor))
        engine.register(_insecure_snmp(vendor))
        engine.register(_unused_interface(vendor))
        engine.register(_overly_permissive_acl(vendor))
        engine.register(_missing_interface_description(vendor))
        engine.register(_no_enable_secret(vendor))
        engine.register(_password_encryption_disabled(vendor))
        engine.register(_vty_without_acl(vendor))
        engine.register(_no_aaa_with_multiple_users(vendor))


def _telnet_enabled(vendor: Vendor) -> Rule:
    def check(device: Device, raw_text: str) -> list[Hit]:
        for svc in device.management:
            if svc.name == "telnet" and svc.enabled:
                return [Hit()]
        return []

    return Rule(
        rule_id="CISCO-SEC-001",
        severity=Severity.HIGH,
        vendor=vendor,
        category=Category.SECURITY,
        title="Telnet enabled for remote management",
        description="VTY lines accept Telnet, which transmits credentials and session data in clear text.",
        recommendation="Restrict `transport input` to `ssh` on all VTY lines and disable Telnet.",
        check=check,
    )


def _http_without_https(vendor: Vendor) -> Rule:
    def check(device: Device, raw_text: str) -> list[Hit]:
        http = next((m for m in device.management if m.name == "http"), None)
        https = next((m for m in device.management if m.name == "https"), None)
        if http and http.enabled and not (https and https.enabled):
            return [Hit()]
        return []

    return Rule(
        rule_id="CISCO-SEC-002",
        severity=Severity.MEDIUM,
        vendor=vendor,
        category=Category.SECURITY,
        title="HTTP management server enabled without HTTPS",
        description="`ip http server` is enabled while `ip http secure-server` is not, exposing the web UI unencrypted.",
        recommendation="Disable `ip http server` or enable `ip http secure-server` and disable the plain HTTP listener.",
        check=check,
    )


def _ssh_not_configured(vendor: Vendor) -> Rule:
    def check(device: Device, raw_text: str) -> list[Hit]:
        ssh = next((m for m in device.management if m.name == "ssh"), None)
        if not ssh or not ssh.enabled:
            return [Hit()]
        return []

    return Rule(
        rule_id="CISCO-SEC-003",
        severity=Severity.MEDIUM,
        vendor=vendor,
        category=Category.SECURITY,
        title="SSH does not appear to be configured",
        description="No evidence of `ip ssh version`, RSA keys, or VTY lines accepting SSH transport was found.",
        recommendation="Configure a domain name, generate RSA keys, and set `transport input ssh` on VTY lines.",
        check=check,
    )


def _weak_password_storage(vendor: Vendor) -> Rule:
    def check(device: Device, raw_text: str) -> list[Hit]:
        hits: list[Hit] = []
        weak_types = {SecretType.PLAINTEXT, SecretType.CISCO_TYPE7}
        if device.security.enable_secret and device.security.enable_secret.secret_type in weak_types:
            hits.append(
                Hit(
                    subject="enable secret",
                    description=(
                        "The enable secret is stored as plaintext or a reversibly-encoded "
                        "(type 7) value rather than a salted hash (type 5/8/9)."
                    ),
                )
            )
        for user in device.users:
            if user.secret_type in weak_types:
                hits.append(
                    Hit(
                        subject=user.username,
                        description=(
                            f"User '{user.username}' has a plaintext or type 7 password instead "
                            "of a salted hash."
                        ),
                    )
                )
        return hits

    return Rule(
        rule_id="CISCO-SEC-004",
        severity=Severity.HIGH,
        vendor=vendor,
        category=Category.SECURITY,
        title="Weak password storage (plaintext or type 7)",
        description="A credential is stored as plaintext or with the reversible type 7 cipher.",
        recommendation="Use `enable secret` / `username ... secret` (type 5 or higher) instead of `password` / type 7.",
        check=check,
    )


def _missing_login_banner(vendor: Vendor) -> Rule:
    def check(device: Device, raw_text: str) -> list[Hit]:
        return [] if device.security.login_banner_present else [Hit()]

    return Rule(
        rule_id="CISCO-BP-001",
        severity=Severity.LOW,
        vendor=vendor,
        category=Category.BEST_PRACTICES,
        title="Missing login banner",
        description="No `banner motd` or `banner login` was found. An authorized-access banner is a common compliance requirement.",
        recommendation="Add `banner motd ^C ... unauthorized access is prohibited ... ^C`.",
        check=check,
    )


def _insecure_snmp(vendor: Vendor) -> Rule:
    def check(device: Device, raw_text: str) -> list[Hit]:
        return [
            Hit(subject="SNMP", description=f"SNMP community '{c}' is a well-known default value.")
            for c in device.snmp.communities
            if c in ("public", "private")
        ]

    return Rule(
        rule_id="CISCO-SEC-005",
        severity=Severity.CRITICAL,
        vendor=vendor,
        category=Category.SECURITY,
        title="Default SNMP community string in use",
        description="A default ('public'/'private') SNMP community string was found.",
        recommendation="Replace default community strings with unique values, or migrate to SNMPv3.",
        check=check,
    )


def _unused_interface(vendor: Vendor) -> Rule:
    def check(device: Device, raw_text: str) -> list[Hit]:
        return [
            Hit(
                subject=iface.name,
                description=(
                    f"{iface.name} has no IP address, no description, and is not "
                    "administratively shut down."
                ),
            )
            for iface in device.interfaces
            if iface.enabled
            and not iface.ipv4
            and not iface.description
            and iface.mode.value != "access"
        ]

    return Rule(
        rule_id="CISCO-AVAIL-001",
        severity=Severity.LOW,
        vendor=vendor,
        category=Category.AVAILABILITY,
        title="Unused interface not administratively disabled",
        description="An interface with no addressing or description is left enabled, increasing attack surface.",
        recommendation="Run `shutdown` on interfaces that are not in active use.",
        check=check,
    )


def _overly_permissive_acl(vendor: Vendor) -> Rule:
    def check(device: Device, raw_text: str) -> list[Hit]:
        hits: list[Hit] = []
        for acl in device.acls:
            for entry in acl.entries:
                if (
                    entry.action == "permit"
                    and entry.source == "any"
                    and entry.destination == "any"
                    and entry.protocol in ("ip", "any")
                ):
                    hits.append(
                        Hit(
                            subject=acl.name,
                            description=f"ACL '{acl.name}' contains an unrestricted `permit ip any any` entry.",
                        )
                    )
        return hits

    return Rule(
        rule_id="CISCO-SEC-006",
        severity=Severity.MEDIUM,
        vendor=vendor,
        category=Category.SECURITY,
        title="Overly permissive ACL entry",
        description="An access list permits all protocols from any source to any destination.",
        recommendation="Scope the ACL to the specific protocols/sources/destinations actually required.",
        check=check,
    )


def _missing_interface_description(vendor: Vendor) -> Rule:
    def check(device: Device, raw_text: str) -> list[Hit]:
        return [
            Hit(subject=iface.name, description=f"{iface.name} carries an IP address but has no description.")
            for iface in device.interfaces
            if iface.ipv4 and not iface.description
        ]

    return Rule(
        rule_id="CISCO-QUAL-001",
        severity=Severity.INFO,
        vendor=vendor,
        category=Category.CONFIG_QUALITY,
        title="Missing description on addressed interface",
        description="An interface with an IP address has no description, which slows down troubleshooting.",
        recommendation="Add a short `description` stating the interface's role (e.g. 'Uplink to Core Switch').",
        check=check,
    )


def _no_enable_secret(vendor: Vendor) -> Rule:
    def check(device: Device, raw_text: str) -> list[Hit]:
        return [] if device.security.enable_secret is not None else [Hit()]

    return Rule(
        rule_id="CISCO-SEC-007",
        severity=Severity.CRITICAL,
        vendor=vendor,
        category=Category.SECURITY,
        title="No enable secret configured",
        description="No `enable secret` (or `enable password`) was found - privileged EXEC access may be unprotected.",
        recommendation="Configure `enable secret <strong-password>` immediately.",
        check=check,
    )


def _password_encryption_disabled(vendor: Vendor) -> Rule:
    def check(device: Device, raw_text: str) -> list[Hit]:
        has_plaintext_line_password = bool(re.search(r"^\s*password (?!7 )\S", raw_text, re.MULTILINE))
        if has_plaintext_line_password and not device.security.service_password_encryption:
            return [Hit()]
        return []

    return Rule(
        rule_id="CISCO-SEC-008",
        severity=Severity.LOW,
        vendor=vendor,
        category=Category.SECURITY,
        title="`service password-encryption` not enabled",
        description="Line/vty passwords appear to be stored in clear text and `service password-encryption` is not set.",
        recommendation="Enable `service password-encryption` (note: this only provides weak/reversible obfuscation - prefer type 5+ secrets where possible).",
        check=check,
    )


def _vty_without_acl(vendor: Vendor) -> Rule:
    def check(device: Device, raw_text: str) -> list[Hit]:
        return [] if device.security.vty_access_class else [Hit()]

    return Rule(
        rule_id="CISCO-SEC-009",
        severity=Severity.MEDIUM,
        vendor=vendor,
        category=Category.SECURITY,
        title="VTY lines without an access-class restriction",
        description="Remote management lines (VTY) do not reference an `access-class`, so any source may attempt to connect.",
        recommendation="Apply `access-class <acl> in` on VTY lines to restrict management access to trusted sources.",
        check=check,
    )


def _no_aaa_with_multiple_users(vendor: Vendor) -> Rule:
    def check(device: Device, raw_text: str) -> list[Hit]:
        if len(device.users) > 1 and not device.security.aaa_new_model:
            return [Hit()]
        return []

    return Rule(
        rule_id="CISCO-MGMT-001",
        severity=Severity.INFO,
        vendor=vendor,
        category=Category.MANAGEMENT,
        title="Multiple local users without AAA",
        description="Several local user accounts exist but `aaa new-model` is not configured.",
        recommendation="Consider centralizing authentication (TACACS+/RADIUS) via AAA for auditability.",
        check=check,
    )
