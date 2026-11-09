"""One discovery pass: pick the adapter, ping-sweep the subnet, read the neighbor table.

The Windows-specific calls live in ``SystemProbe`` so tests can swap in a fake
probe that returns simulated adapters, ping replies, and neighbor entries.
"""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import logging
import os
import subprocess  # noqa: S404 - fixed PowerShell/arp commands, no user input
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol

from netwatch.discovery import ping as ping_mod
from netwatch.discovery.adapters import (
    POWERSHELL_ADAPTERS,
    Adapter,
    AdapterChoice,
    choose_home_adapter,
    parse_adapters_json,
)
from netwatch.discovery.neighbors import (
    CONFIRMED_STATES,
    POWERSHELL_NEIGHBORS,
    Neighbor,
    parse_arp_a,
    parse_netneighbor_json,
    usable_neighbors,
)
from netwatch.netutil import UnsafeTargetError, scan_hosts, validate_scan_subnet
from netwatch.timeutil import utcnow

log = logging.getLogger("netwatch.discovery")


@dataclass(frozen=True)
class Observation:
    ip: str
    mac: str
    replied: bool  # answered the ping
    state: str  # neighbor-table state ("self" for this PC)


@dataclass
class DiscoveryResult:
    started_at: datetime
    finished_at: datetime | None = None
    choice: AdapterChoice | None = None
    subnets: list[ipaddress.IPv4Network] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    replied: int = 0
    error: str | None = None

    @property
    def gateway_ip(self) -> str | None:
        return self.choice.gateway if self.choice else None

    @property
    def local_ip(self) -> str | None:
        return self.choice.local_ip if self.choice else None

    @property
    def vpn_up(self) -> list[str]:
        return self.choice.vpn_up if self.choice else []

    def mac_for(self, ip: str | None) -> str | None:
        return next((o.mac for o in self.observations if o.ip == ip), None)


class Probe(Protocol):
    def adapters(self) -> list[Adapter]: ...
    def neighbors(self, if_index: int, local_ip: str | None) -> list[Neighbor]: ...
    async def sweep(self, hosts: list[str]) -> set[str]: ...


# ---------------------------------------------------------------- real system calls


def system_exe(*parts: str) -> str:
    """Full path under System32, so a planted exe earlier on PATH is never run."""
    return os.path.join(os.environ.get("SYSTEMROOT", r"C:\Windows"), "System32", *parts)


def run_powershell(script: str, timeout: int = 45) -> str:
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    exe = system_exe("WindowsPowerShell", "v1.0", "powershell.exe")
    r = subprocess.run(  # noqa: S603 - fixed script
        [exe, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    if r.returncode != 0:
        err = r.stderr.decode("utf-8", errors="replace").strip().splitlines()
        raise RuntimeError(f"PowerShell failed: {err[0] if err else r.returncode}")
    return r.stdout.decode("utf-8", errors="replace")


@dataclass
class SystemProbe:
    concurrency: int = 64
    timeout_ms: int = 700

    def adapters(self) -> list[Adapter]:
        return parse_adapters_json(run_powershell(POWERSHELL_ADAPTERS))

    def neighbors(self, if_index: int, local_ip: str | None) -> list[Neighbor]:
        try:
            script = POWERSHELL_NEIGHBORS.replace("{if_index}", str(int(if_index)))
            return parse_netneighbor_json(run_powershell(script))
        except (RuntimeError, ValueError, OSError, subprocess.TimeoutExpired) as exc:
            log.warning("Get-NetNeighbor failed (%s); falling back to arp -a", exc)
        arp = system_exe("ARP.EXE")
        r = subprocess.run([arp, "-a"], capture_output=True, timeout=30, check=False)  # noqa: S603
        return parse_arp_a(r.stdout.decode("utf-8", errors="replace"), local_ip)

    async def sweep(self, hosts: list[str]) -> set[str]:
        return await ping_mod.sweep(hosts, concurrency=self.concurrency, timeout_ms=self.timeout_ms)


# ---------------------------------------------------------------- the pass


def pick_subnets(choice: AdapterChoice, override: list[str], *, allow_sample=False):
    if override:
        return [validate_scan_subnet(s, allow_sample=allow_sample) for s in override]
    if not choice.ok:
        raise UnsafeTargetError("No home network adapter found (one with a default gateway).")
    return [validate_scan_subnet(choice.subnet, allow_sample=allow_sample)]


def build_observations(
    neighbors: list[Neighbor],
    replied: set[str],
    subnets: list[ipaddress.IPv4Network],
    choice: AdapterChoice,
) -> list[Observation]:
    """A device counts as seen if it answered the ping, or Windows just confirmed its MAC
    (devices that ignore pings, like many phones, still answer the ARP lookup)."""
    seen: dict[str, Observation] = {}
    for net in subnets:
        for n in usable_neighbors(neighbors, net):
            if n.ip in replied or n.state in CONFIRMED_STATES:
                seen[n.ip] = Observation(n.ip, n.mac, n.ip in replied, n.state)
    me = choice.local_ip
    my_mac = choice.adapter.mac if choice.adapter else ""
    if me and my_mac and any(ipaddress.IPv4Address(me) in net for net in subnets):
        seen[me] = Observation(me, my_mac, True, "self")
    return sorted(seen.values(), key=lambda o: ipaddress.IPv4Address(o.ip))


async def discover(
    probe: Probe,
    *,
    subnet_override: list[str] | None = None,
    adapter_override: str = "",
    settle_seconds: float = 4.0,
    allow_sample: bool = False,
) -> DiscoveryResult:
    result = DiscoveryResult(started_at=utcnow())
    try:
        adapters = await asyncio.to_thread(probe.adapters)
        choice = choose_home_adapter(adapters, adapter_override, allow_sample=allow_sample)
        result.choice = choice
        result.subnets = pick_subnets(choice, subnet_override or [], allow_sample=allow_sample)
        hosts = [h for net in result.subnets for h in scan_hosts(net) if h != choice.local_ip]
        replied = await probe.sweep(hosts)
        result.replied = len(replied)
        if settle_seconds:
            # Let Windows finish its ARP lookups for devices that ignore pings.
            await asyncio.sleep(settle_seconds)
        if_index = choice.adapter.if_index if choice.adapter else 0
        neighbors = await asyncio.to_thread(probe.neighbors, if_index, choice.local_ip)
        result.observations = build_observations(neighbors, replied, result.subnets, choice)
    except UnsafeTargetError as exc:
        result.error = str(exc)
    except Exception as exc:  # recorded on the scan run and shown in the app
        log.exception("Discovery failed")
        result.error = f"Discovery failed: {exc}"
    result.finished_at = utcnow()
    return result
