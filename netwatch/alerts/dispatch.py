"""Deliver pending alerts through the configured senders, with retries.

Rules:
- Each alert row is one event (dedup happens when it's created), so it's sent once.
- A failed send is recorded (attempts, error, next retry) and retried with backoff,
  forever. The app shows a banner while anything is failing or undelivered.
- During quiet hours only high-priority alerts (gateway MAC change) go out; the
  rest wait until quiet hours end.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from netwatch.alerts.base import AlertSender, SendError
from netwatch.alerts.render import render_alert
from netwatch.models import Alert

log = logging.getLogger("netwatch.alerts")
BACKOFF_SECONDS = [60, 300, 900, 1800, 3600]


def next_delay(attempts: int) -> timedelta:
    return timedelta(seconds=BACKOFF_SECONDS[min(attempts, len(BACKOFF_SECONDS)) - 1])


@dataclass
class DeliveryReport:
    sent: list[int] = field(default_factory=list)
    failed: list[int] = field(default_factory=list)
    held_for_quiet_hours: int = 0
    no_channel: bool = False


def due_alerts(s: Session, now: datetime) -> list[Alert]:
    return list(
        s.scalars(
            select(Alert)
            .where(
                Alert.sent_ok.is_(False),
                or_(Alert.next_attempt_at.is_(None), Alert.next_attempt_at <= now),
            )
            .order_by(Alert.created_at, Alert.id)
        )
    )


def deliver_pending(
    s: Session,
    senders: list[AlertSender],
    now: datetime,
    *,
    base_url: str,
    quiet: bool = False,
) -> DeliveryReport:
    report = DeliveryReport()
    pending = due_alerts(s, now)
    if not senders:
        report.no_channel = bool(pending)
        return report
    for alert in pending:
        if quiet and alert.severity != "high":
            report.held_for_quiet_hours += 1
            continue
        message = render_alert(alert, base_url)
        errors = []
        delivered = False
        for sender in senders:
            try:
                sender.send(message)
                delivered = True
            except SendError as exc:
                errors.append(f"{sender.name}: {exc}")
            except Exception as exc:  # a bug in a sender must not stop the others
                log.exception("Alert sender %s crashed", sender.name)
                errors.append(f"{sender.name}: unexpected error: {exc}")
        alert.send_attempts += 1
        if delivered:
            alert.sent_ok = True
            alert.sent_at = now
            alert.next_attempt_at = None
            alert.last_error = "; ".join(errors)  # partial failures stay visible
            report.sent.append(alert.id)
        else:
            alert.last_error = "; ".join(errors) or "no sender accepted the alert"
            alert.next_attempt_at = now + next_delay(alert.send_attempts)
            report.failed.append(alert.id)
            log.error(
                "Alert %s not delivered (attempt %d): %s",
                alert.id,
                alert.send_attempts,
                alert.last_error,
            )
    s.flush()
    return report


@dataclass
class DeliveryStatus:
    channel_configured: bool
    unsent: int
    failing: int
    last_error: str
    oldest_unsent: datetime | None

    @property
    def problem(self) -> str:
        if self.failing:
            return f"{self.failing} alert(s) failed to send and will be retried. Last error: {self.last_error}"
        if self.unsent and not self.channel_configured:
            return f"{self.unsent} alert(s) waiting: no alert channel is set up yet."
        return ""


def delivery_status(s: Session, channel_configured: bool) -> DeliveryStatus:
    unsent = s.scalar(select(func.count()).select_from(Alert).where(Alert.sent_ok.is_(False))) or 0
    failing_q = select(Alert).where(Alert.sent_ok.is_(False), Alert.send_attempts > 0)
    failing = list(s.scalars(failing_q.order_by(Alert.id.desc())))
    oldest = s.scalar(select(func.min(Alert.created_at)).where(Alert.sent_ok.is_(False)))
    return DeliveryStatus(
        channel_configured=channel_configured,
        unsent=unsent,
        failing=len(failing),
        last_error=failing[0].last_error if failing else "",
        oldest_unsent=oldest,
    )


def senders_from_config(cfg) -> list[AlertSender]:
    """Build the configured senders. Email arrives in phase 3; until then there are none,
    alerts queue up, and the app says so with a banner."""
    return []
