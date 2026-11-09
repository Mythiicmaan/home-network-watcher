"""Fill a database with the FAKE sample network: a week of history, port checks, alerts.

Used by ``python -m netwatch sample-data``, the demo server, tests, and README screens.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from netwatch.models import Device, PortScan, ScanRun, Sighting
from netwatch.ports import risky_findings
from netwatch.sample import SAMPLE_DEVICES, SAMPLE_GATEWAY_IP, SAMPLE_SUBNET
from netwatch.services.common import GATEWAY_IP_KEY, GATEWAY_MAC_KEY, create_alert, set_setting
from netwatch.services.inventory import device_facts

# Hours (local-ish) each device tends to be around; None = always on.
PRESENCE = {
    "Alex's Phone": (7, 23),
    "Sam's Phone": (6, 22),
    "Sam's Laptop": (8, 21),
    "Living Room TV": (17, 23),
    "Game Console": (15, 21),
}


def build_sample_db(s: Session, now: datetime, days: int = 7, step_minutes: int = 30) -> None:
    if s.scalar(select(func.count()).select_from(Device)):
        return
    rng = random.Random(42)
    start = now - timedelta(days=days)
    devices: list[tuple[Device, object]] = []
    for i, sd in enumerate(SAMPLE_DEVICES):
        newcomer = sd.status == "unknown"
        first = now - timedelta(hours=30 + 20 * i) if newcomer else start
        d = Device(
            mac=sd.mac,
            is_randomized_mac=sd.randomized,
            vendor=sd.vendor,
            hostname=sd.hostname,
            hostname_source="mdns" if sd.hostname else "",
            friendly_name=sd.friendly_name,
            owner=sd.owner,
            status=sd.status,
            first_seen=first,
            last_seen=first,
            last_ip=sd.ip,
            is_gateway=sd.ip == SAMPLE_GATEWAY_IP,
            in_baseline=not newcomer,
            names_checked_at=now,
        )
        s.add(d)
        devices.append((d, sd))
    s.flush()

    t = start
    while t <= now:
        run = ScanRun(
            started_at=t,
            finished_at=t + timedelta(seconds=16),
            ok=True,
            subnet=SAMPLE_SUBNET,
            adapter="Ethernet (Example PCIe GbE Controller)",
            gateway_ip=SAMPLE_GATEWAY_IP,
        )
        s.add(run)
        s.flush()
        found = 0
        for d, sd in devices:
            if t < d.first_seen:
                continue
            window = PRESENCE.get(sd.friendly_name)
            present = window is None or window[0] <= t.hour < window[1]
            if sd.status == "unknown":
                present = rng.random() < 0.5
            if t >= now - timedelta(minutes=step_minutes * 2):
                present = present or sd.friendly_name in ("Alex's Phone", "Living Room TV")
            if present:
                s.add(Sighting(device_id=d.id, scan_run_id=run.id, ip=sd.ip, seen_at=t))
                d.last_seen = t
                found += 1
        run.hosts_found = found
        t += timedelta(minutes=step_minutes)

    set_setting(s, GATEWAY_MAC_KEY, SAMPLE_DEVICES[0].mac)
    set_setting(s, GATEWAY_IP_KEY, SAMPLE_GATEWAY_IP)

    for d, sd in devices:
        ports = [{"port": p, "service": ""} for p in sd.open_ports]
        done = d.first_seen + timedelta(minutes=6)
        s.add(
            PortScan(
                device_id=d.id,
                ip=sd.ip,
                status="done",
                reason="baseline" if d.in_baseline else "new",
                method="nmap",
                requested_at=d.first_seen,
                started_at=d.first_seen + timedelta(minutes=5),
                finished_at=done,
                open_ports=ports,
                risky_ports=risky_findings(list(sd.open_ports)),
            )
        )
        if not d.in_baseline:
            a = create_alert(
                s,
                kind="new_device",
                dedup_key=f"new_device:{d.mac}",
                title=f"New device joined: {d.hostname or d.vendor or 'Unknown device'}",
                message="A device that has never been seen before joined the home network.",
                severity="warning",
                device_id=d.id,
                facts=device_facts(d),
                now=d.first_seen,
            )
            a.sent_ok, a.sent_at, a.send_attempts = True, d.first_seen, 1
        for f in risky_findings(list(sd.open_ports)):
            if sd.status == "ignored" or d.in_baseline and f["port"] in (80, 445):
                continue
            a = create_alert(
                s,
                kind="risky_port",
                dedup_key=f"risky_port:{d.id}:{f['port']}",
                title=f"Risky port open on {d.display_name}: {f['port']} ({f['service']})",
                message=f"{f['why']}\n\nWhat to do: {f['fix']}",
                severity=f["severity"],
                device_id=d.id,
                facts=[("Device", d.display_name), ("Port", f"{f['port']}/tcp")],
                now=done,
            )
            if a:
                a.sent_ok, a.sent_at, a.send_attempts = True, done, 1
                a.acknowledged = d.in_baseline
    s.flush()
