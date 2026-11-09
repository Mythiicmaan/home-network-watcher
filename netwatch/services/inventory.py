"""Apply one discovery pass to the database: devices, sightings, scan health, alerts."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from netwatch import detect
from netwatch.discovery.oui import VendorDB
from netwatch.discovery.scan import DiscoveryResult
from netwatch.models import Device, PortScan, ScanRun, Sighting
from netwatch.netutil import is_locally_administered
from netwatch.services.common import (
    GATEWAY_IP_KEY,
    GATEWAY_MAC_KEY,
    create_alert,
    get_setting,
    set_setting,
)


@dataclass
class ApplyReport:
    scan_run_id: int
    health: detect.ScanHealth
    baseline: bool = False
    new_device_ids: list[int] = field(default_factory=list)
    alert_ids: list[int] = field(default_factory=list)
    port_scans_queued: int = 0


def good_scans(s: Session, limit: int) -> list[ScanRun]:
    return list(
        s.scalars(
            select(ScanRun)
            .where(ScanRun.ok.is_(True), ScanRun.degraded.is_(False))
            .order_by(ScanRun.started_at.desc(), ScanRun.id.desc())
            .limit(limit)
        )
    )


def known_macs(s: Session) -> set[str]:
    return set(s.scalars(select(Device.mac)))


def queue_port_scan(s: Session, device: Device, reason: str) -> PortScan | None:
    """Queue a port check unless one is already waiting or running for this device."""
    busy = s.scalar(
        select(PortScan.id).where(
            PortScan.device_id == device.id, PortScan.status.in_(("queued", "running"))
        )
    )
    if busy:
        return None
    scan = PortScan(device_id=device.id, ip=device.last_ip, reason=reason, status="queued")
    s.add(scan)
    s.flush()
    return scan


def _ip_history(s: Session, runs: list[ScanRun]) -> list[dict[str, str]]:
    """{ip: mac} per scan, oldest first."""
    out = []
    for run in sorted(runs, key=lambda r: (r.started_at, r.id)):
        rows = s.execute(
            select(Sighting.ip, Device.mac)
            .join(Device, Device.id == Sighting.device_id)
            .where(Sighting.scan_run_id == run.id)
        )
        out.append({ip: mac for ip, mac in rows})
    return out


def apply_discovery(
    s: Session,
    result: DiscoveryResult,
    *,
    vendors: VendorDB,
    names: dict[str, tuple[str, str]] | None = None,
    degraded_ratio: float = 0.3,
    auto_port_check: bool = True,
    now: datetime | None = None,
) -> ApplyReport:
    """Record the scan. Degraded scans update last-seen for known devices only: they never
    add devices, mark anything offline, or create alerts."""
    names = names or {}
    now = now or result.finished_at or result.started_at
    run = ScanRun(
        started_at=result.started_at,
        finished_at=result.finished_at or now,
        hosts_found=len(result.observations),
        subnet=", ".join(str(n) for n in result.subnets),
        adapter=(result.choice.adapter.label if result.choice and result.choice.adapter else ""),
        gateway_ip=result.gateway_ip or "",
    )
    s.add(run)
    s.flush()

    previous = good_scans(s, 12)
    previous = [r for r in previous if r.id != run.id]
    gateway_seen = result.mac_for(result.gateway_ip) is not None
    health = detect.assess_scan(
        error=result.error,
        found=len(result.observations),
        typical=detect.typical_device_count([r.hosts_found for r in previous]),
        gateway_ip=result.gateway_ip,
        gateway_seen=gateway_seen,
        vpn_up=result.vpn_up,
        ratio=degraded_ratio,
    )
    run.ok, run.degraded, run.error = health.ok, health.degraded, health.reason
    report = ApplyReport(scan_run_id=run.id, health=health)
    if not health.ok:
        return report

    baseline = not previous and not health.degraded
    report.baseline = baseline
    by_mac = {d.mac: d for d in s.scalars(select(Device))}
    trusted_gw = get_setting(s, GATEWAY_MAC_KEY)

    for obs in result.observations:
        device = by_mac.get(obs.mac)
        if device is None:
            if health.degraded:
                continue  # the next good scan will pick it up and alert properly
            name, source = names.get(obs.mac, ("", ""))
            device = Device(
                mac=obs.mac,
                is_randomized_mac=is_locally_administered(obs.mac),
                vendor=vendors.lookup(obs.mac),
                hostname=name,
                hostname_source=source,
                names_checked_at=now if obs.mac in names else None,
                first_seen=now,
                last_seen=now,
                last_ip=obs.ip,
                in_baseline=baseline,
            )
            s.add(device)
            s.flush()
            by_mac[obs.mac] = device
            report.new_device_ids.append(device.id)
            if not baseline:
                alert = _new_device_alert(s, device, now)
                if alert:
                    report.alert_ids.append(alert.id)
            if auto_port_check and queue_port_scan(s, device, "baseline" if baseline else "new"):
                report.port_scans_queued += 1
        device.last_seen = now
        device.last_ip = obs.ip
        device.is_gateway = obs.ip == result.gateway_ip and (
            trusted_gw is None or trusted_gw == obs.mac
        )
        s.add(Sighting(device_id=device.id, scan_run_id=run.id, ip=obs.ip, seen_at=now))
    s.flush()

    if health.degraded:
        return report

    # ---- gateway MAC (ARP spoofing) ----
    ip_to_mac = {o.ip: o.mac for o in result.observations}
    finding = detect.check_gateway(result.gateway_ip, trusted_gw, ip_to_mac)
    if finding and finding.first_sighting:
        set_setting(s, GATEWAY_MAC_KEY, finding.observed_mac)
        set_setting(s, GATEWAY_IP_KEY, finding.gateway_ip)
    elif finding and finding.changed:
        alert = _gateway_alert(s, finding, by_mac.get(finding.observed_mac), now)
        if alert:
            report.alert_ids.append(alert.id)

    # ---- IP conflicts ----
    history = _ip_history(s, [*previous[:3], run])
    skip = {result.gateway_ip} if result.gateway_ip else set()
    for conflict in detect.find_ip_conflicts(history, skip_ips=skip):
        alert = _conflict_alert(s, conflict, by_mac, now)
        if alert:
            report.alert_ids.append(alert.id)
    return report


# ---------------------------------------------------------------- alert text


def device_facts(d: Device) -> list[tuple[str, str]]:
    facts = [
        (
            "Vendor",
            d.vendor or ("Private/randomized address" if d.is_randomized_mac else "Unknown"),
        ),
        ("Hostname", d.hostname or "(none)"),
        ("IP address", d.last_ip),
        ("MAC address", d.mac),
    ]
    if d.is_randomized_mac:
        facts.append(("Note", "Private/randomized MAC (phones and tablets do this)"))
    return facts


def _new_device_alert(s: Session, d: Device, now: datetime):
    label = d.hostname or d.vendor or "Unknown device"
    return create_alert(
        s,
        kind="new_device",
        dedup_key=f"new_device:{d.mac}",
        title=f"New device joined: {label}",
        message=(
            "A device that has never been seen before joined the home network.\n\n"
            "If you recognize it, open it and mark it Known (and give it a name). "
            "If you don't, check the gateway's device list."
        ),
        severity="warning",
        device_id=d.id,
        facts=device_facts(d),
        now=now,
    )


def _gateway_alert(s: Session, f: detect.GatewayFinding, device: Device | None, now: datetime):
    facts = [
        ("Gateway IP", f.gateway_ip),
        ("Trusted gateway MAC", f.trusted_mac or ""),
        ("MAC answering now", f.observed_mac),
    ]
    if f.also_claimed_by:
        facts.append(("Same MAC also answers for", ", ".join(f.also_claimed_by)))
    return create_alert(
        s,
        kind="gateway_mac_change",
        dedup_key=f.dedup_key,
        title="Gateway MAC address changed (possible ARP spoofing)",
        message=(
            "The router's IP address is now answered by a different MAC address. This is the "
            "classic sign of ARP spoofing (MITRE ATT&CK T1557.002), where another device "
            "pretends to be the router to intercept traffic.\n\n"
            "If you just replaced or reset the gateway, accept the new MAC in Settings. "
            "Otherwise, find the device with this MAC and disconnect it."
        ),
        severity="high",
        device_id=device.id if device else None,
        facts=facts,
        extra={"trusted_mac": f.trusted_mac, "observed_mac": f.observed_mac},
        now=now,
    )


def _conflict_alert(s: Session, c: detect.IpConflict, by_mac: dict[str, Device], now: datetime):
    devices = [by_mac[m] for m in c.macs if m in by_mac]
    facts = [("IP address", c.ip)] + [
        (f"Device {i + 1}", f"{d.display_name} ({d.mac})") for i, d in enumerate(devices)
    ]
    return create_alert(
        s,
        kind="ip_conflict",
        dedup_key=c.dedup_key,
        title=f"IP conflict: two devices claim {c.ip}",
        message=(
            "Two different devices keep answering for the same IP address. Usually this is a "
            "device with a hard-coded (static) IP that overlaps DHCP, but it can also be a "
            "sign of ARP spoofing (MITRE ATT&CK T1557.002)."
        ),
        severity="warning",
        device_id=devices[0].id if devices else None,
        facts=facts,
        extra={"macs": list(c.macs)},
        now=now,
    )


def accept_gateway_mac(s: Session, mac: str) -> None:
    """The owner confirms a gateway change (e.g. a replaced router)."""
    set_setting(s, GATEWAY_MAC_KEY, mac)
