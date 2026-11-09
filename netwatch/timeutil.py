"""Times are stored as naive UTC and shown in the PC's local time zone."""

from __future__ import annotations

from datetime import UTC, datetime


def utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def to_local(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt.replace(tzinfo=UTC).astimezone().replace(tzinfo=None)


def local_to_utc(dt: datetime) -> datetime:
    return dt.astimezone(UTC).replace(tzinfo=None)
