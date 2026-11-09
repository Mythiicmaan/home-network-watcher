"""Detection rules, as pure functions over simulated-or-real scan data.

Nothing here touches the network. Every rule is proven with simulated data
in tests/test_detect.py; nothing is ever spoofed on the real network.

MITRE ATT&CK mapping:
- Gateway MAC changed      -> T1557.002 Adversary-in-the-Middle: ARP Cache Poisoning
- IP conflict (MAC flip)   -> T1557.002 (also misconfiguration / duplicate static IP)
- New device               -> T1200 Hardware Additions (rogue device on the network)
- Risky open port          -> T1021 Remote Services / T1133 External Remote Services
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass
from datetime import datetime, time

# ---------------------------------------------------------------- scan health


@dataclass(frozen=True)
class ScanHealth:
    ok: bool  # the scan ran
    degraded: bool  # it ran but looks broken: never mark offline or alert from it
    reason: str = ""


def typical_device_count(recent_counts: list[int], min_samples: int = 3) -> int | None:
    """Median of recent good scans' device counts (None until there's enough history)."""
    counts = [c for c in recent_counts if c > 0]
    if len(counts) < min_samples:
        return None
    return int(statistics.median(counts))


def assess_scan(
    *,
    error: str | None,
    found: int,
    typical: int | None,
    gateway_ip: str | None,
    gateway_seen: bool,
    vpn_up: list[str],
    ratio: float = 0.3,
) -> ScanHealth:
    if error:
        return ScanHealth(ok=False, degraded=False, reason=error)
    problems = []
    if gateway_ip and not gateway_seen:
        problems.append("the gateway didn't answer")
    if typical and found < ratio * typical:
        problems.append(f"found {found} devices, usually {typical}")
    if found == 0:
        problems.append("no devices found")
    if not problems:
        return ScanHealth(ok=True, degraded=False)
    hint = f" A VPN is connected ({', '.join(vpn_up)})." if vpn_up else " Is a VPN connected?"
    reason = "Scan degraded: " + "; ".join(problems) + "." + hint
    return ScanHealth(ok=True, degraded=True, reason=reason)


# ---------------------------------------------------------------- gateway MAC


@dataclass(frozen=True)
class GatewayFinding:
    gateway_ip: str
    trusted_mac: str | None
    observed_mac: str
    also_claimed_by: tuple[str, ...] = ()  # other IPs answering with the new MAC

    @property
    def first_sighting(self) -> bool:
        return self.trusted_mac is None

    @property
    def changed(self) -> bool:
        return self.trusted_mac is not None and self.trusted_mac != self.observed_mac

    @property
    def dedup_key(self) -> str:
        return f"gateway_mac_change:{self.trusted_mac}>{self.observed_mac}"


def check_gateway(
    gateway_ip: str | None, trusted_mac: str | None, ip_to_mac: dict[str, str]
) -> GatewayFinding | None:
    """Compare the gateway's MAC with the trusted one.

    Returns None if the gateway wasn't seen. ``first_sighting`` means: store it as
    trusted (no alert). ``changed`` means: the classic sign of ARP spoofing, alert.
    The trusted MAC is only replaced when the owner accepts the change.
    """
    if not gateway_ip:
        return None
    observed = ip_to_mac.get(gateway_ip)
    if not observed:
        return None
    others = tuple(
        sorted(ip for ip, mac in ip_to_mac.items() if mac == observed and ip != gateway_ip)
    )
    return GatewayFinding(gateway_ip, trusted_mac, observed, others)


# ---------------------------------------------------------------- IP conflicts


@dataclass(frozen=True)
class IpConflict:
    ip: str
    macs: tuple[str, ...]

    @property
    def dedup_key(self) -> str:
        return f"ip_conflict:{self.ip}:{'|'.join(self.macs)}"


def find_ip_conflicts(
    history: list[dict[str, str]], *, window: int = 4, skip_ips: set[str] | None = None
) -> list[IpConflict]:
    """Two devices claiming one IP at the same time.

    Windows keeps one MAC per IP, so a live conflict shows up as the IP's MAC
    flip-flopping between scans: A, then B, then A again within ``window`` scans.
    A one-way change (A then B) is normal DHCP reuse after A left, so it's ignored.

    ``history``: one {ip: mac} map per good scan, oldest first; the last is current.
    """
    skip_ips = skip_ips or set()
    recent = history[-window:]
    if len(recent) < 3:
        return []
    out = []
    for ip in sorted(recent[-1]):
        if ip in skip_ips:
            continue
        seq = [scan[ip] for scan in recent if ip in scan]
        # Collapse runs: A A B B A -> A B A
        runs = [m for i, m in enumerate(seq) if i == 0 or m != seq[i - 1]]
        if len(runs) >= 3 and len(set(runs)) < len(runs):
            out.append(IpConflict(ip, tuple(sorted(set(runs)))))
    return out


# ---------------------------------------------------------------- devices


def new_macs(observed: list[str], known: set[str]) -> list[str]:
    seen: list[str] = []
    for mac in observed:
        if mac not in known and mac not in seen:
            seen.append(mac)
    return seen


def online_cutoff(good_scan_starts: list[datetime], scans: int = 2) -> datetime | None:
    """A device is online if seen in the last ``scans`` good (non-degraded) scans.

    Returns the start time of the oldest of those scans: last_seen >= cutoff means online.
    Degraded scans aren't in the list, so they can never make a device look offline.
    """
    if not good_scan_starts:
        return None
    ordered = sorted(good_scan_starts, reverse=True)
    return ordered[min(scans, len(ordered)) - 1]


def is_online(last_seen: datetime | None, cutoff: datetime | None) -> bool:
    return bool(last_seen and cutoff and last_seen >= cutoff)


def is_returning_unknown(status: str, distinct_days: int, min_days: int = 3) -> bool:
    """An unknown device that keeps coming back (seen on several different days)."""
    return status == "unknown" and distinct_days >= min_days


# ---------------------------------------------------------------- schedule helpers


def in_quiet_hours(now_local: time, window: tuple[time, time] | None) -> bool:
    if not window:
        return False
    start, end = window
    if start == end:
        return False
    if start < end:
        return start <= now_local < end
    return now_local >= start or now_local < end  # spans midnight


def week_key(d: datetime) -> str:
    y, w, _ = d.isocalendar()
    return f"{y}-W{w:02d}"


def digest_due(now_local: datetime, weekday: int, hour: int, last_sent_week: str | None) -> bool:
    """Weekly digest: on ``weekday`` (0=Mon) at/after ``hour``, once per ISO week."""
    if now_local.weekday() != weekday or now_local.hour < hour:
        return False
    return last_sent_week != week_key(now_local)
