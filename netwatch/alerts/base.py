"""The alert channel interface.

A sender takes one rendered message and either delivers it or raises
``SendError``. The dispatcher (``netwatch.alerts.dispatch``) handles retries,
backoff, quiet hours, and recording failures so they're never silent.

Email (Gmail SMTP) is added in phase 3; others (Pushover, ntfy) can be added
later by implementing ``AlertSender``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

SUBJECT_PREFIX = "[NetWatch]"


class SendError(Exception):
    """Delivery failed. The message is shown in the app and the alert is retried."""


@dataclass(frozen=True)
class OutgoingAlert:
    subject: str
    text: str
    html: str
    severity: str = "info"


@runtime_checkable
class AlertSender(Protocol):
    name: str

    def send(self, message: OutgoingAlert) -> None:
        """Deliver the message or raise SendError."""
        ...
