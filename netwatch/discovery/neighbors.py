"""Read Windows' IPv4 neighbor (ARP) table.

Primary: ``Get-NetNeighbor`` as JSON. Fallback: ``arp -a`` text. Both work for
a standard account and only read what Windows already learned.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass

from netwatch.netutil import is_unicast_device_mac, normalize_mac

POWERSHELL_NEIGHBORS = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$rows = @(Get-NetNeighbor -AddressFamily IPv4 -InterfaceIndex {if_index} | ForEach-Object {
  [pscustomobject]@{
    ip    = [string]$_.IPAddress
    mac   = [string]$_.LinkLayerAddress
    state = [string]$_.State
  }
})
ConvertTo-Json -InputObject $rows -Compress
"""

# States where Windows holds a usable MAC for the address.
VALID_STATES = {"reachable", "stale", "delay", "probe", "permanent", "dynamic", "static"}
# States that confirm the device answered just now (used with the ping result).
CONFIRMED_STATES = {"reachable", "delay", "probe"}


@dataclass(frozen=True)
class Neighbor:
    ip: str
    mac: str
    state: str  # lowercase: reachable | stale | delay | probe | permanent | dynamic | static ...


def parse_netneighbor_json(text: str) -> list[Neighbor]:
    if not text.strip():
        return []
    data = json.loads(text)
    rows = data if isinstance(data, list) else [data]
    out = []
    for row in rows:
        mac = normalize_mac(str(row.get("mac") or ""))
        state = str(row.get("state") or "").strip().lower()
        ip = str(row.get("ip") or "").strip()
        if mac and ip:
            out.append(Neighbor(ip, mac, state))
    return out


_ARP_LINE = re.compile(
    r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9A-Fa-f]{2}(?:[-:][0-9A-Fa-f]{2}){5})\s+(\S+)\s*$"
)
_ARP_IFACE = re.compile(r"^\S.*?(\d{1,3}(?:\.\d{1,3}){3})\s+-+\s+0x([0-9a-fA-F]+)")


def parse_arp_a(text: str, local_ip: str | None = None) -> list[Neighbor]:
    """Parse ``arp -a``. If ``local_ip`` is given, only that interface's section is used.

    The column headers are localized, so only the data lines are matched.
    """
    out = []
    current_ok = local_ip is None
    for line in text.splitlines():
        iface = _ARP_IFACE.match(line)
        if iface:
            current_ok = local_ip is None or iface.group(1) == local_ip
            continue
        m = _ARP_LINE.match(line)
        if m and current_ok:
            mac = normalize_mac(m.group(2))
            if mac:
                out.append(Neighbor(m.group(1), mac, m.group(3).lower()))
    return out


def usable_neighbors(neighbors: list[Neighbor], subnet: ipaddress.IPv4Network) -> list[Neighbor]:
    """Unicast devices inside the subnet with a usable table entry (one per IP)."""
    out: dict[str, Neighbor] = {}
    for n in neighbors:
        if n.state not in VALID_STATES or not is_unicast_device_mac(n.mac):
            continue
        try:
            addr = ipaddress.IPv4Address(n.ip)
        except ValueError:
            continue
        if addr not in subnet or addr in (subnet.network_address, subnet.broadcast_address):
            continue
        out[n.ip] = n
    return list(out.values())
