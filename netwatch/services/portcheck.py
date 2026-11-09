"""Port-check queue: pick the next device, record results, alert on risky ports."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from netwatch.models import Device, PortScan
from netwatch.ports import PortResult, risky_findings
from netwatch.services.common import create_alert


def recover_interrupted(s: Session) -> int:
    """Checks left 'running' by a crash or restart go back in the queue."""
    r = s.execute(update(PortScan).where(PortScan.status == "running").values(status="queued"))
    return r.rowcount or 0


def next_queued(s: Session) -> PortScan | None:
    return s.scalar(
        select(PortScan)
        .where(PortScan.status == "queued")
        .order_by(PortScan.reason != "manual", PortScan.requested_at, PortScan.id)
        .limit(1)
    )


def start(s: Session, scan: PortScan, now: datetime) -> str:
    scan.status = "running"
    scan.started_at = now
    scan.ip = scan.device.last_ip
    s.flush()
    return scan.ip


def finish(s: Session, scan: PortScan, result: PortResult, now: datetime) -> list[int]:
    """Store results; one risky_port alert per device+port (never for ignored devices)."""
    scan.finished_at = now
    scan.method = result.method
    if result.error:
        scan.status = "failed"
        scan.error = result.error
        s.flush()
        return []
    scan.status = "done"
    scan.error = result.note
    scan.open_ports = result.open_ports
    findings = risky_findings(result.ports)
    scan.risky_ports = findings
    device: Device = scan.device
    alert_ids = []
    if device.status != "ignored":
        for f in findings:
            alert = create_alert(
                s,
                kind="risky_port",
                dedup_key=f"risky_port:{device.id}:{f['port']}",
                title=f"Risky port open on {device.display_name}: {f['port']} ({f['service']})",
                message=f"{f['why']}\n\nWhat to do: {f['fix']}",
                severity=f["severity"],
                device_id=device.id,
                facts=[
                    ("Device", device.display_name),
                    ("IP address", scan.ip),
                    ("Port", f"{f['port']}/tcp ({f['service']})"),
                ],
                now=now,
            )
            if alert:
                alert_ids.append(alert.id)
    s.flush()
    return alert_ids


def latest_result(s: Session, device_id: int) -> PortScan | None:
    return s.scalar(
        select(PortScan)
        .where(PortScan.device_id == device_id, PortScan.status.in_(("done", "failed")))
        .order_by(PortScan.id.desc())
        .limit(1)
    )
