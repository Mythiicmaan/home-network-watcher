"""Deliver pending alerts through the configured senders, with retries.

Rules:
- Each alert row is one event (dedup happens when it's created), so it's sent once.
- A failed send is recorded (attempts, error, next retry) and retried with backoff,
  forever. The app shows a banner while anything is failing or undelivered.
- During quiet hours only high-priority alerts (gateway MAC change) go out; the
  rest wait until quiet hours end.
- When two or more ordinary alerts are waiting at once, they go out as one summary
  email. High-priority alerts and the weekly digest are always sent on their own.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from netwatch.alerts.base import SUBJECT_PREFIX, AlertSender, OutgoingAlert, SendError
from netwatch.alerts.render import render_alert, render_summary
from netwatch.models import Alert

log = logging.getLogger("netwatch.alerts")
BACKOFF_SECONDS = [60, 300, 900, 1800, 3600]
SUMMARY_MIN = 2  # this many ordinary alerts waiting at once -> one summary email


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
    sendable = []
    for alert in pending:
        if quiet and alert.severity != "high":
            report.held_for_quiet_hours += 1
        else:
            sendable.append(alert)
    # High-priority alerts and digests always go on their own. When several others are
    # waiting (e.g. the first port checks, or a busy night), they go in one summary email.
    solo = [a for a in sendable if a.severity == "high" or a.kind == "digest"]
    rest = [a for a in sendable if a not in solo]
    groups: list[list[Alert]] = [[a] for a in solo]
    if len(rest) >= SUMMARY_MIN:
        groups.append(rest)
    else:
        groups += [[a] for a in rest]

    for group in groups:
        if len(group) == 1:
            message = render_alert(group[0], base_url)
        else:
            message = render_summary(group, base_url)
        delivered, errors = _send(senders, message)
        for alert in group:
            _record(alert, delivered, errors, now, report)
    s.flush()
    return report


def _send(senders: list[AlertSender], message: OutgoingAlert) -> tuple[bool, list[str]]:
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
    return delivered, errors


def _record(alert: Alert, delivered: bool, errors: list[str], now, report) -> None:
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
    """The configured senders: email when [alerts.email] in config.toml is complete."""
    from netwatch.alerts.email import EmailSender, email_settings

    settings, _problem = email_settings(cfg)
    return [EmailSender(settings)] if settings else []


def channel_problem(cfg) -> str:
    """Why the alert channel can't be used (empty when fine or simply not set up)."""
    from netwatch.alerts.email import email_settings

    return email_settings(cfg)[1]


def send_test_alert(cfg) -> tuple[bool, str]:
    """Send a test message through every configured sender. Returns (ok, detail)."""
    problem = channel_problem(cfg)
    if problem:
        return False, problem
    senders = senders_from_config(cfg)
    if not senders:
        return False, "No alert channel is set up. Add [alerts.email] to config.toml."
    base = cfg.public_base_url
    message = OutgoingAlert(
        subject=f"{SUBJECT_PREFIX} Test alert",
        text=(
            "This is a test from Home Network Watcher. If you can read it, email alerts work.\n\n"
            f"Open the app: {base}\n"
        ),
        html=(
            "<div style='font-family:Segoe UI,Arial,sans-serif;font-size:15px'>"
            "<h2 style='font-size:18px'>Test alert</h2>"
            "<p>This is a test from Home Network Watcher. If you can read it, email alerts work.</p>"
            f"<p><a href='{base}'>Open the app</a></p></div>"
        ),
    )
    delivered, errors = _send(senders, message)
    if delivered:
        return True, "; ".join(errors)
    log.error("Test alert failed: %s", "; ".join(errors))
    return False, "; ".join(errors)
