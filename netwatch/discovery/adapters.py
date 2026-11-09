"""Pick the home network adapter.

Rule: the active, physical adapter that has an IPv4 default gateway and a
private address. VPNs (NordVPN, Windscribe, WireGuard, OpenVPN, ...),
Tailscale, and virtual adapters (VirtualBox, Hyper-V, VMware) are ignored.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field

from netwatch.netutil import (
    LINK_LOCAL_V4,
    SAMPLE_RANGE,
    TAILSCALE_V4,
    is_private_v4,
    normalize_mac,
)

# Read-only; works for a standard (non-admin) account.
POWERSHELL_ADAPTERS = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$rows = @(Get-NetIPConfiguration -All | ForEach-Object {
  $na = $_.NetAdapter
  [pscustomobject]@{
    alias       = [string]$_.InterfaceAlias
    description = [string]$_.InterfaceDescription
    if_index    = [int]$_.InterfaceIndex
    status      = if ($na) { [string]$na.Status } else { '' }
    hardware    = if ($na) { [bool]$na.HardwareInterface } else { $false }
    virtual     = if ($na) { [bool]$na.Virtual } else { $true }
    media       = if ($na) { [string]$na.PhysicalMediaType } else { '' }
    mac         = if ($na) { [string]$na.MacAddress } else { '' }
    ipv4        = @($_.IPv4Address | ForEach-Object { [pscustomobject]@{ ip = [string]$_.IPAddress; prefix = [int]$_.PrefixLength } })
    gateways    = @($_.IPv4DefaultGateway | ForEach-Object { [string]$_.NextHop })
  }
})
ConvertTo-Json -InputObject $rows -Depth 4 -Compress
"""

# Lowercase substrings of an adapter's name or description that mark it as not-home.
IGNORE_KEYWORDS = (
    "vpn",
    "nordlynx",
    "windscribe",
    "wireguard",
    "openvpn",
    "tap-",
    "tap adapter",
    "wintun",
    "tailscale",
    "zerotier",
    "hamachi",
    "anyconnect",
    "fortinet",
    "pangp",
    "virtualbox",
    "vmware",
    "hyper-v",
    "vethernet",
    "virtual",
    "loopback",
    "bluetooth",
    "npcap",
)
VPN_KEYWORDS = (
    "vpn",
    "nordlynx",
    "windscribe",
    "wireguard",
    "openvpn",
    "tap-",
    "wintun",
    "anyconnect",
    "fortinet",
    "pangp",
    "zerotier",
)


@dataclass
class Adapter:
    alias: str
    description: str
    if_index: int
    status: str
    hardware: bool
    virtual: bool
    media: str = ""
    mac: str = ""
    ipv4: list[tuple[str, int]] = field(default_factory=list)
    gateways: list[str] = field(default_factory=list)

    @property
    def up(self) -> bool:
        return self.status.lower() == "up"

    @property
    def label(self) -> str:
        return f"{self.alias} ({self.description})" if self.description else self.alias

    def text(self) -> str:
        return f"{self.alias} {self.description}".lower()

    @property
    def wired(self) -> bool:
        return "802.3" in self.media


@dataclass
class AdapterChoice:
    adapter: Adapter | None
    subnet: ipaddress.IPv4Network | None
    gateway: str | None
    local_ip: str | None
    skipped: list[tuple[str, str]] = field(default_factory=list)  # (adapter label, reason)
    vpn_up: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.adapter is not None and self.subnet is not None


def _as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def parse_adapters_json(text: str) -> list[Adapter]:
    data = json.loads(text) if text.strip() else []
    out = []
    for row in _as_list(data):
        ipv4 = []
        for a in _as_list(row.get("ipv4")):
            if isinstance(a, dict) and a.get("ip"):
                ipv4.append((str(a["ip"]), int(a.get("prefix") or 32)))
        out.append(
            Adapter(
                alias=str(row.get("alias") or ""),
                description=str(row.get("description") or ""),
                if_index=int(row.get("if_index") or 0),
                status=str(row.get("status") or ""),
                hardware=bool(row.get("hardware")),
                virtual=bool(row.get("virtual")),
                media=str(row.get("media") or ""),
                mac=normalize_mac(str(row.get("mac") or "")) or "",
                ipv4=ipv4,
                gateways=[str(g) for g in _as_list(row.get("gateways")) if g],
            )
        )
    return out


def is_vpn(adapter: Adapter) -> bool:
    return any(k in adapter.text() for k in VPN_KEYWORDS)


def _usable_address(adapter: Adapter, allow_sample: bool = False) -> tuple[str, int] | None:
    for ip, prefix in adapter.ipv4:
        try:
            addr = ipaddress.IPv4Address(ip)
        except ValueError:
            continue
        if addr in TAILSCALE_V4 or addr in LINK_LOCAL_V4 or addr.is_loopback:
            continue
        if (is_private_v4(addr) or (allow_sample and addr in SAMPLE_RANGE)) and prefix < 32:
            return ip, prefix
    return None


def skip_reason(adapter: Adapter, allow_sample: bool = False) -> str | None:
    """Why this adapter can't be the home network (None = it qualifies)."""
    if not adapter.up:
        return "not connected"
    text = adapter.text()
    for k in IGNORE_KEYWORDS:
        if k in text:
            return f"VPN/virtual adapter ({k.strip('-')})"
    if adapter.virtual:
        return "virtual adapter"
    if not adapter.gateways:
        return "no default gateway"
    if _usable_address(adapter, allow_sample) is None:
        return "no private IPv4 address"
    return None


def choose_home_adapter(
    adapters: list[Adapter], override_alias: str = "", *, allow_sample: bool = False
) -> AdapterChoice:
    skipped: list[tuple[str, str]] = []
    candidates: list[Adapter] = []
    for a in adapters:
        if override_alias:
            if a.alias.lower() == override_alias.lower():
                candidates.append(a)
            continue
        reason = skip_reason(a, allow_sample)
        if reason:
            skipped.append((a.label, reason))
        else:
            candidates.append(a)
    vpn_up = [a.label for a in adapters if a.up and is_vpn(a)]
    # Physical hardware first, wired before wireless, then the lowest interface index.
    candidates.sort(key=lambda a: (not a.hardware, not a.wired, a.if_index))
    for a in candidates:
        addr = _usable_address(a, allow_sample)
        if addr is None:
            skipped.append((a.label, "no private IPv4 address"))
            continue
        ip, prefix = addr
        net = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
        gw = next((g for g in a.gateways if ipaddress.IPv4Address(g) in net), None)
        return AdapterChoice(a, net, gw, ip, skipped, vpn_up)
    return AdapterChoice(None, None, None, None, skipped, vpn_up)
