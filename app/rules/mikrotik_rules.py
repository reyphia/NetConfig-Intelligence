from __future__ import annotations

import re

from app.models.device import Device, Vendor
from app.models.findings import Category, Severity
from app.rules.engine import Hit, Rule, RuleEngine

_VENDOR = Vendor.MIKROTIK_ROUTEROS
_UNRESTRICTED_MGMT_SERVICES = {"telnet", "ftp", "www", "ssh", "winbox", "api", "api-ssl", "www-ssl"}


def register_all(engine: RuleEngine) -> None:
    engine.register(_telnet_enabled())
    engine.register(_management_exposed_unrestricted())
    engine.register(_http_without_https())
    engine.register(_weak_firewall_input_policy())
    engine.register(_suspicious_nat_no_interface())
    engine.register(_dns_remote_requests())
    engine.register(_default_snmp_community())
    engine.register(_default_admin_user())
    engine.register(_ftp_enabled())


def _telnet_enabled() -> Rule:
    def check(device: Device, raw_text: str) -> list[Hit]:
        svc = next((m for m in device.management if m.name == "telnet"), None)
        return [Hit()] if svc and svc.enabled else []

    return Rule(
        rule_id="MTK-SEC-001",
        severity=Severity.HIGH,
        vendor=_VENDOR,
        category=Category.SECURITY,
        title="Telnet service enabled",
        description="The Telnet service is enabled, exposing clear-text remote management.",
        recommendation="Run `/ip service disable telnet` unless there is a specific legacy requirement.",
        check=check,
    )


def _management_exposed_unrestricted() -> Rule:
    def check(device: Device, raw_text: str) -> list[Hit]:
        hits: list[Hit] = []
        for svc in device.management:
            if svc.name in ("winbox", "ssh", "api", "api-ssl") and svc.enabled and not svc.allowed_sources:
                hits.append(
                    Hit(
                        subject=svc.name,
                        description=(
                            f"The '{svc.name}' service is enabled with no source-address "
                            "restriction (`address=`), so it can be reached from any network "
                            "the router is connected to, including the WAN if routed."
                        ),
                    )
                )
        return hits

    return Rule(
        rule_id="MTK-SEC-002",
        severity=Severity.HIGH,
        vendor=_VENDOR,
        category=Category.SECURITY,
        title="Management service exposed without source restriction",
        description="A management service has no `address=` allow-list configured.",
        recommendation="Set `/ip service set <service> address=<trusted-cidr>` to restrict who can reach it.",
        check=check,
    )


def _http_without_https() -> Rule:
    def check(device: Device, raw_text: str) -> list[Hit]:
        www = next((m for m in device.management if m.name == "www"), None)
        www_ssl = next((m for m in device.management if m.name == "www-ssl"), None)
        if www and www.enabled and not (www_ssl and www_ssl.enabled):
            return [Hit()]
        return []

    return Rule(
        rule_id="MTK-SEC-003",
        severity=Severity.MEDIUM,
        vendor=_VENDOR,
        category=Category.SECURITY,
        title="WebFig (HTTP) enabled without HTTPS",
        description="The plain `www` service is enabled while `www-ssl` is not.",
        recommendation="Enable `www-ssl` with a valid certificate and disable plain `www`.",
        check=check,
    )


def _weak_firewall_input_policy() -> Rule:
    def check(device: Device, raw_text: str) -> list[Hit]:
        input_entries = [
            e for acl in device.acls if acl.kind == "firewall_filter" for e in acl.entries
            if "chain=input" in (e.raw or "")
        ]
        if not input_entries:
            return [Hit(description="No `chain=input` firewall filter rules were found - the input chain default policy (accept) applies to everything reaching the router itself.")]
        has_final_drop = any(e.action == "deny" for e in input_entries)
        if not has_final_drop:
            return [
                Hit(
                    description=(
                        "The input chain has filter rules but none of them `drop`/`reject` - "
                        "traffic not matched by an earlier rule falls through to the router's "
                        "default accept policy."
                    )
                )
            ]
        return []

    return Rule(
        rule_id="MTK-SEC-004",
        severity=Severity.HIGH,
        vendor=_VENDOR,
        category=Category.SECURITY,
        title="Weak or missing input chain firewall policy",
        description="The firewall does not appear to end the input chain with an explicit drop rule.",
        recommendation="Add rules to accept established/related and explicitly required traffic, then `add chain=input action=drop`.",
        check=check,
    )


def _suspicious_nat_no_interface() -> Rule:
    def check(device: Device, raw_text: str) -> list[Hit]:
        return [
            Hit(description="A `masquerade` NAT rule has no `out-interface` set, so it applies to every interface, including any future WAN-facing ones.")
            for rule in device.nat_rules
            if rule.kind == "masquerade" and not rule.interface
        ]

    return Rule(
        rule_id="MTK-SEC-005",
        severity=Severity.MEDIUM,
        vendor=_VENDOR,
        category=Category.SECURITY,
        title="Masquerade NAT rule without out-interface restriction",
        description="A masquerade rule applies to all interfaces rather than a specific WAN interface.",
        recommendation="Scope the rule with `out-interface=<wan-interface>` (or an interface list) to avoid masquerading unintended traffic.",
        check=check,
    )


def _dns_remote_requests() -> Rule:
    def check(device: Device, raw_text: str) -> list[Hit]:
        if re.search(r"/ip dns[^\n]*\n(?:.*\n)*?set[^\n]*allow-remote-requests=yes", raw_text) or (
            "allow-remote-requests=yes" in raw_text
        ):
            return [Hit()]
        return []

    return Rule(
        rule_id="MTK-SEC-006",
        severity=Severity.MEDIUM,
        vendor=_VENDOR,
        category=Category.SECURITY,
        title="Router DNS resolver open to remote requests",
        description="`allow-remote-requests=yes` turns the router into an open DNS resolver unless firewalled off.",
        recommendation="Disable remote DNS requests, or restrict who can reach UDP/TCP 53 on the router via the firewall.",
        check=check,
    )


def _default_snmp_community() -> Rule:
    def check(device: Device, raw_text: str) -> list[Hit]:
        return [
            Hit(description=f"SNMP community '{c}' is a well-known default value.")
            for c in device.snmp.communities
            if c == "public"
        ]

    return Rule(
        rule_id="MTK-SEC-007",
        severity=Severity.CRITICAL,
        vendor=_VENDOR,
        category=Category.SECURITY,
        title="Default SNMP community string in use",
        description="The default 'public' SNMP community was found.",
        recommendation="Replace it with a unique community string, or restrict SNMP with a firewall rule / disable it if unused.",
        check=check,
    )


def _default_admin_user() -> Rule:
    def check(device: Device, raw_text: str) -> list[Hit]:
        return [Hit()] if any(u.username == "admin" for u in device.users) else []

    return Rule(
        rule_id="MTK-BP-001",
        severity=Severity.LOW,
        vendor=_VENDOR,
        category=Category.BEST_PRACTICES,
        title="Default 'admin' account still present",
        description="A user named 'admin' exists, which is a predictable target for credential attacks.",
        recommendation="Create a uniquely-named administrative account and remove/disable the default 'admin' user.",
        check=check,
    )


def _ftp_enabled() -> Rule:
    def check(device: Device, raw_text: str) -> list[Hit]:
        svc = next((m for m in device.management if m.name == "ftp"), None)
        return [Hit()] if svc and svc.enabled else []

    return Rule(
        rule_id="MTK-QUAL-001",
        severity=Severity.LOW,
        vendor=_VENDOR,
        category=Category.CONFIG_QUALITY,
        title="Unused FTP service left enabled",
        description="The FTP service is enabled; it is rarely needed and adds unencrypted attack surface.",
        recommendation="Disable FTP unless it is actively used: `/ip service disable ftp`.",
        check=check,
    )
