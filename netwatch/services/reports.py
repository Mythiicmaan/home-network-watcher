"""Read-side queries: online status, summary counts, weekly digest, timelines, rollup."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from netwatch import detect
from netwatch.models import Alert, Device, PortScan, PresenceHour, ScanRun, Sighting
from netwatch.services.common import LAST_DIGEST_WEEK_KEY, create_alert, get_setting, set_setting
from netwatch.services.inventory import good_scans

ROLLUP_AFTER_DAYS = 30


def online_cutoff(s: Session) -> datetime | None:
    return detect.online_cutoff([r.started_at for r in good_scans(s, 2)])


def online_ids(s: Session) -> set[int]:
    cutoff = online_cutoff(s)
    if cutoff is None:
        return set()
    return set(s.scalars(select(Device.id).where(Device.last_seen >= cutoff)))


def last_scan(s: Session) -> ScanRun | None:
    return s.scalar(select(ScanRun).order_by(ScanRun.started_at.desc(), ScanRun.id.desc()).limit(1))


def last_good_scan(s: Session) -> ScanRun | None:
    runs = good_scans(s, 1)
    return runs[0] if runs else None


def distinct_days_seen(s: Session, device_id: int, since: datetime) -> int:
    day = func.date(Sighting.seen_at)
    return (
        s.scalar(
            select(func.count(func.distinct(day))).where(
                Sighting.device_id == device_id, Sighting.seen_at >= since
            )
        )
        or 0
    )


def returning_unknowns(s: Session, now: datetime, days: int = 14) -> list[tuple[Device, int]]:
    since = now - timedelta(days=days)
    out = []
    for d in s.scalars(select(Device).where(Device.status == "unknown")):
        n = distinct_days_seen(s, d.id, since)
        if detect.is_returning_unknown(d.status, n):
            out.append((d, n))
    return out


def latest_risky(s: Session) -> list[tuple[Device, PortScan]]:
    """Devices whose most recent finished port check found risky ports (ignored excluded)."""
    latest = (
        select(PortScan.device_id, func.max(PortScan.id).label("pid"))
        .where(PortScan.status == "done")
        .group_by(PortScan.device_id)
        .subquery()
    )
    rows = s.execute(
        select(Device, PortScan)
        .join(latest, latest.c.device_id == Device.id)
        .join(PortScan, PortScan.id == latest.c.pid)
        .where(Device.status != "ignored")
    )
    return [(d, p) for d, p in rows if p.risky_ports]


@dataclass
class Summary:
    devices: int
    online: int
    unknown: int
    new_this_week: int
    last_scan: ScanRun | None
    last_good_scan: ScanRun | None
    last_alert: Alert | None
    unacknowledged: int


def summary(s: Session, now: datetime) -> Summary:
    count = lambda q: s.scalar(select(func.count()).select_from(Device).where(q)) or 0  # noqa: E731
    return Summary(
        devices=s.scalar(select(func.count()).select_from(Device)) or 0,
        online=len(online_ids(s)),
        unknown=count(Device.status == "unknown"),
        new_this_week=count(Device.first_seen >= now - timedelta(days=7)),
        last_scan=last_scan(s),
        last_good_scan=last_good_scan(s),
        last_alert=s.scalar(
            select(Alert).where(Alert.kind != "digest").order_by(Alert.id.desc()).limit(1)
        ),
        unacknowledged=s.scalar(
            select(func.count()).select_from(Alert).where(Alert.acknowledged.is_(False))
        )
        or 0,
    )


# ---------------------------------------------------------------- weekly digest


def maybe_create_digest(s: Session, now_utc: datetime, now_local: datetime, cfg) -> Alert | None:
    last_week = get_setting(s, LAST_DIGEST_WEEK_KEY)
    if not detect.digest_due(now_local, cfg.digest_weekday, cfg.digest_hour, last_week):
        return None
    key = detect.week_key(now_local)
    sm = summary(s, now_utc)
    new = list(s.scalars(select(Device).where(Device.first_seen >= now_utc - timedelta(days=7))))
    unknown = returning_unknowns(s, now_utc)
    risky = latest_risky(s)
    lines = [f"{sm.devices} devices known, {sm.online} online now, {sm.unknown} not yet named."]
    lines.append(
        "New this week: " + (", ".join(d.display_name for d in new) if new else "none") + "."
    )
    if unknown:
        lines.append(
            "Unknown devices that keep coming back: "
            + ", ".join(f"{d.display_name} ({n} days)" for d, n in unknown)
            + "."
        )
    if risky:
        lines.append(
            "Risky ports still open: "
            + "; ".join(
                f"{d.display_name}: " + ", ".join(str(r["port"]) for r in p.risky_ports)
                for d, p in risky
            )
            + "."
        )
    alert = create_alert(
        s,
        kind="digest",
        dedup_key=f"digest:{key}",
        title=f"Weekly network digest ({key})",
        message="\n\n".join(lines),
        facts=[
            ("Devices", str(sm.devices)),
            ("New this week", str(len(new))),
            ("Unknown, returning", str(len(unknown))),
            ("Devices with risky ports", str(len(risky))),
        ],
        now=now_utc,
    )
    set_setting(s, LAST_DIGEST_WEEK_KEY, key)
    return alert


# ---------------------------------------------------------------- history


def presence_timeline(
    s: Session, device_id: int, now: datetime, days: int = 7
) -> list[tuple[datetime, bool]]:
    """One (hour, seen) pair per hour for the last ``days`` days (UTC hours)."""
    start = (now - timedelta(days=days)).replace(minute=0, second=0, microsecond=0)
    hour = func.strftime("%Y-%m-%d %H:00:00", Sighting.seen_at)
    seen = {
        datetime.fromisoformat(h)
        for h in s.scalars(
            select(hour)
            .where(Sighting.device_id == device_id, Sighting.seen_at >= start)
            .distinct()
        )
    }
    out = []
    t = start
    while t <= now:
        out.append((t, t in seen))
        t += timedelta(hours=1)
    return out


def rollup_old_sightings(s: Session, now: datetime, keep_days: int = ROLLUP_AFTER_DAYS) -> int:
    """Fold sightings older than ``keep_days`` into hourly presence rows, then delete them."""
    cutoff = now - timedelta(days=keep_days)
    hour = func.strftime("%Y-%m-%d %H:00:00", Sighting.seen_at)
    rows = s.execute(
        select(Sighting.device_id, hour, func.count(), func.max(Sighting.ip))
        .where(Sighting.seen_at < cutoff)
        .group_by(Sighting.device_id, hour)
    ).all()
    for device_id, h, n, ip in rows:
        when = datetime.fromisoformat(h)
        existing = s.scalar(
            select(PresenceHour).where(
                PresenceHour.device_id == device_id, PresenceHour.hour == when
            )
        )
        if existing:
            existing.sightings += n
            existing.last_ip = ip
        else:
            s.add(PresenceHour(device_id=device_id, hour=when, sightings=n, last_ip=ip))
    result = s.execute(delete(Sighting).where(Sighting.seen_at < cutoff))
    s.flush()
    return result.rowcount or 0
