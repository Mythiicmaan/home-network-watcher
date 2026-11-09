"""Settings and alert creation shared by the services."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from netwatch.models import Alert, Setting
from netwatch.timeutil import utcnow

GATEWAY_MAC_KEY = "gateway_mac"
GATEWAY_IP_KEY = "gateway_ip"
LAST_DIGEST_WEEK_KEY = "last_digest_week"
OUI_PROBLEM_KEY = "oui_problem"


class NetwatchError(ValueError):
    """A user-facing problem (shown as a message, not a crash)."""


def get_setting(s: Session, key: str, default: str | None = None) -> str | None:
    row = s.get(Setting, key)
    return row.value if row else default


def set_setting(s: Session, key: str, value: str) -> None:
    row = s.get(Setting, key)
    if row:
        row.value = value
    else:
        s.add(Setting(key=key, value=value))


def create_alert(
    s: Session,
    *,
    kind: str,
    dedup_key: str,
    title: str,
    message: str,
    severity: str = "info",
    device_id: int | None = None,
    facts: list[tuple[str, str]] | None = None,
    extra: dict | None = None,
    now: datetime | None = None,
) -> Alert | None:
    """Create the alert unless this exact event was already alerted (returns None then)."""
    if s.scalar(select(Alert.id).where(Alert.dedup_key == dedup_key)):
        return None
    alert = Alert(
        kind=kind,
        dedup_key=dedup_key,
        title=title,
        message=message,
        severity=severity,
        device_id=device_id,
        details={"facts": [list(f) for f in (facts or [])], **(extra or {})},
        created_at=now or utcnow(),
    )
    s.add(alert)
    s.flush()
    return alert
