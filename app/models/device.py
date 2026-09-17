"""Vendor-neutral normalized configuration model.

Every vendor parser produces a `Device` instance. Every renderer consumes a
`Device` instance. Analyzers, the editor and the replay-plan builder all work
against this model instead of raw text, so adding a new vendor only means
writing a parser + renderer pair - the rest of the application does not
change.
"""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field


class Vendor(str, Enum):
    CISCO_IOS = "cisco_ios"
    CISCO_IOS_XE = "cisco_iosxe"
    MIKROTIK_ROUTEROS = "mikrotik_routeros"
    UNKNOWN = "unknown"


class SecretType(str, Enum):
    PLAINTEXT = "plaintext"  # e.g. `password 0 foo`, stored in clear in the file
    CISCO_TYPE7 = "cisco_type7"  # reversible XOR cipher
    CISCO_TYPE5 = "cisco_type5"  # MD5-crypt, one-way
    CISCO_TYPE8 = "cisco_type8"  # PBKDF2-SHA256, one-way
    CISCO_TYPE9 = "cisco_type9"  # scrypt, one-way
    UNKNOWN_HASH = "unknown_hash"


class IPv4Interface(BaseModel):
    address: str
    prefix_length: int
    secondary: bool = False


class IPv6Interface(BaseModel):
    address: str
    prefix_length: int


class InterfaceMode(str, Enum):
    ROUTED = "routed"
    ACCESS = "access"
    TRUNK = "trunk"
    UNKNOWN = "unknown"


class Interface(BaseModel):
    name: str
    description: str | None = None
    enabled: bool = True
    ipv4: list[IPv4Interface] = Field(default_factory=list)
    ipv6: list[IPv6Interface] = Field(default_factory=list)
    vlan: int | None = None
    trunk_allowed_vlans: list[int] = Field(default_factory=list)
    mode: InterfaceMode = InterfaceMode.UNKNOWN
    mtu: int | None = None
    inbound_acl: str | None = None
    outbound_acl: str | None = None
    raw_block: str | None = None  # original lines, for provenance / raw view


class Vlan(BaseModel):
    id: int
    name: str | None = None
    interfaces: list[str] = Field(default_factory=list)


class StaticRoute(BaseModel):
    network: str
    prefix_length: int
    next_hop: str | None = None
    interface: str | None = None
    metric: int | None = None
    vrf: str | None = None


class AccessControlEntry(BaseModel):
    sequence: int | None = None
    action: Literal["permit", "deny"]
    protocol: str = "ip"
    source: str
    destination: str
    source_port: str | None = None
    destination_port: str | None = None
    # MikroTik: `src-address-list=`/`dst-address-list=` - matches against a
    # named `/ip firewall address-list` rather than a literal address.
    source_address_list: str | None = None
    destination_address_list: str | None = None
    # MikroTik: `in-interface-list=`/`out-interface-list=` - matches against
    # a named `/interface list` rather than a single interface.
    in_interface_list: str | None = None
    out_interface_list: str | None = None
    raw: str | None = None


class AccessControlList(BaseModel):
    name: str
    kind: Literal["standard", "extended", "firewall_filter"] = "extended"
    entries: list[AccessControlEntry] = Field(default_factory=list)
    applied_to: list[str] = Field(default_factory=list)  # interface names using it


class NATRule(BaseModel):
    kind: Literal["static", "dynamic", "masquerade", "src-nat", "dst-nat"] = "masquerade"
    source: str | None = None
    destination: str | None = None
    translated: str | None = None
    interface: str | None = None
    # Cisco: the ACL name/number from `ip nat inside source list <acl> ...`.
    source_acl: str | None = None
    # MikroTik: the address-list name from `src-address-list=`.
    source_address_list: str | None = None
    raw: str | None = None


class DHCPPool(BaseModel):
    name: str
    network: str | None = None
    prefix_length: int | None = None
    range_start: str | None = None
    range_end: str | None = None
    gateway: str | None = None
    dns_servers: list[str] = Field(default_factory=list)
    lease_time: str | None = None
    # MikroTik: the `address-pool=` name a `/ip dhcp-server` references,
    # regardless of whether an `/ip pool` with that name actually exists.
    address_pool: str | None = None


class UserAccount(BaseModel):
    username: str
    privilege: int | None = None
    secret_type: SecretType = SecretType.UNKNOWN_HASH
    secret_raw: str  # the raw value as found in the file (hash or plaintext)
    group: str | None = None  # e.g. mikrotik "full"/"read"/"write"


class ManagementService(BaseModel):
    name: str  # ssh, telnet, http, https, winbox, api, api-ssl, ftp
    enabled: bool
    allowed_sources: list[str] = Field(default_factory=list)  # ACL/address-list names or CIDRs
    port: int | None = None


class SNMPConfig(BaseModel):
    enabled: bool = False
    communities: list[str] = Field(default_factory=list)  # raw community strings
    version: str | None = None
    allowed_sources: list[str] = Field(default_factory=list)


class RoutingConfig(BaseModel):
    static_routes: list[StaticRoute] = Field(default_factory=list)
    default_gateway: str | None = None
    routing_protocols: list[str] = Field(default_factory=list)  # names only, e.g. "ospf 1"


class SecurityConfig(BaseModel):
    enable_secret: UserAccount | None = None
    login_banner_present: bool = False
    aaa_new_model: bool = False
    service_password_encryption: bool = False
    vty_access_class: str | None = None  # ACL name applied to `line vty` via `access-class ... in`


class Device(BaseModel):
    vendor: Vendor
    platform: str
    hostname: str | None = None

    interfaces: list[Interface] = Field(default_factory=list)
    vlans: list[Vlan] = Field(default_factory=list)
    routing: RoutingConfig = Field(default_factory=RoutingConfig)
    acls: list[AccessControlList] = Field(default_factory=list)
    nat_rules: list[NATRule] = Field(default_factory=list)
    # MikroTik: names actually defined via `/ip firewall address-list`,
    # `/interface list`, and `/ip pool` - used to catch rules/DHCP servers
    # that reference a name nothing ever defines.
    address_lists: list[str] = Field(default_factory=list)
    interface_lists: list[str] = Field(default_factory=list)
    ip_pools: list[str] = Field(default_factory=list)
    dns_servers: list[str] = Field(default_factory=list)
    dhcp_pools: list[DHCPPool] = Field(default_factory=list)
    users: list[UserAccount] = Field(default_factory=list)
    management: list[ManagementService] = Field(default_factory=list)
    snmp: SNMPConfig = Field(default_factory=SNMPConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)

    unparsed_lines: list[str] = Field(default_factory=list)  # lines the parser did not model

    def get_interface(self, name: str) -> Interface | None:
        for iface in self.interfaces:
            if iface.name == name:
                return iface
        return None
