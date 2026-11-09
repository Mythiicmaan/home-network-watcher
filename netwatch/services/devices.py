"""Device list (search/sort/filter) and edits."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from netwatch.models import DEVICE_STATUSES, Alert, Device
from netwatch.services.common import NetwatchError
from netwatch.timeutil import utcnow

SORTS = {
    "name": lambda d, online: (d.display_name.lower(),),
    "ip": lambda d, online: (_ip_key(d.last_ip),),
    "vendor": lambda d, online: ((d.vendor or "~").lower(), d.display_name.lower()),
    "last_seen": lambda d, online: (-d.last_seen.timestamp(),),
    "first_seen": lambda d, online: (-d.first_seen.timestamp(),),
    "status": lambda d, online: (DEVICE_STATUSES.index(d.status), d.display_name.lower()),
    "online": lambda d, online: (
        d.id not in online,
        DEVICE_STATUSES.index(d.status),
        _ip_key(d.last_ip),
    ),
}


def _ip_key(ip: str) -> int:
    try:
        return int(ipaddress.IPv4Address(ip))
    except ValueError:
        return 1 << 33


@dataclass
class DeviceRow:
    device: Device
    online: bool


def list_devices(
    s: Session,
    online: set[int],
    *,
    q: str = "",
    status: str = "",
    sort: str = "online",
    reverse: bool = False,
) -> list[DeviceRow]:
    query = select(Device)
    if status in DEVICE_STATUSES:
        query = query.where(Device.status == status)
    devices = list(s.scalars(query))
    needle = q.strip().lower()
    if needle:
        devices = [
            d
            for d in devices
            if any(
                needle in (v or "").lower()
                for v in (d.friendly_name, d.owner, d.vendor, d.hostname, d.last_ip, d.mac, d.notes)
            )
        ]
    key = SORTS.get(sort, SORTS["online"])
    devices.sort(key=lambda d: key(d, online), reverse=reverse)
    return [DeviceRow(d, d.id in online) for d in devices]


def update_device(
    s: Session,
    device: Device,
    *,
    friendly_name: str | None = None,
    owner: str | None = None,
    notes: str | None = None,
    status: str | None = None,
) -> None:
    if friendly_name is not None:
        device.friendly_name = friendly_name.strip()[:120]
    if owner is not None:
        device.owner = owner.strip()[:120]
    if notes is not None:
        device.notes = notes.strip()[:4000]
    if status is not None:
        set_status(s, device, status)


def set_status(s: Session, device: Device, status: str) -> None:
    if status not in DEVICE_STATUSES:
        raise NetwatchError("Unknown status.")
    device.status = status
    if status in ("known", "ignored"):
        # Marking a device Known/Ignored settles its new-device alert.
        now = utcnow()
        for a in s.scalars(
            select(Alert).where(
                Alert.device_id == device.id,
                Alert.kind == "new_device",
                Alert.acknowledged.is_(False),
            )
        ):
            a.acknowledged, a.acknowledged_at = True, now


def get_device(s: Session, device_id: int) -> Device:
    d = s.get(Device, device_id)
    if d is None:
        raise NetwatchError("That device doesn't exist.")
    return d
