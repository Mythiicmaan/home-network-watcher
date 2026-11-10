"""Email alerts through Gmail SMTP (smtp.gmail.com:587, STARTTLS) with an app password.

Everything comes from ``[alerts.email]`` in config.toml (outside the repo).
The password never appears in errors, logs, or the web pages.
"""

from __future__ import annotations

import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid

from netwatch.alerts.base import OutgoingAlert, SendError

# Used instead of the PC's name in the SMTP greeting and Message-IDs, so the computer
# name never ends up in email headers.
NEUTRAL_HOST = "home-network-watcher"
FROM_NAME = "Home Network Watcher"
PLACEHOLDER_DOMAINS = ("example.com", "example.org", "example.net")


@dataclass(frozen=True)
class EmailSettings:
    host: str
    port: int
    username: str
    app_password: str
    to: str

    @property
    def masked_to(self) -> str:
        return mask_address(self.to)


def mask_address(addr: str) -> str:
    local, _, domain = addr.partition("@")
    return f"{local[:1]}***@{domain}" if domain else "***"


def _looks_like_address(value: str) -> bool:
    local, at, domain = value.partition("@")
    return bool(local and at and "." in domain and " " not in value)


def email_settings(cfg) -> tuple[EmailSettings | None, str]:
    """Return (settings, problem). No [alerts.email] section at all = (None, "")."""
    raw = cfg.email
    if not raw:
        return None, ""
    problems = []
    username = str(raw.get("username", "")).strip()
    to = str(raw.get("to", "") or username).strip()
    password = "".join(str(raw.get("app_password", "")).split())  # Google shows it with spaces
    host = str(raw.get("smtp_host", "smtp.gmail.com")).strip()
    try:
        port = int(raw.get("smtp_port", 587))
    except (TypeError, ValueError):
        port = 0
        problems.append("smtp_port must be a number (587)")
    for label, value in (("username", username), ("to", to)):
        if not _looks_like_address(value):
            problems.append(f"{label} is not an email address")
        elif value.lower().endswith(PLACEHOLDER_DOMAINS):
            problems.append(f"{label} is still the example address")
    if not password or "paste" in password.lower():
        problems.append("app_password is missing")
    elif len(password) != 16:
        problems.append("app_password should be the 16-letter app password from Google")
    if not host:
        problems.append("smtp_host is missing")
    if problems:
        return None, "Email settings in config.toml need fixing: " + "; ".join(problems) + "."
    return EmailSettings(host, port, username, password, to), ""


def build_message(settings: EmailSettings, alert: OutgoingAlert) -> EmailMessage:
    msg = EmailMessage()
    msg["Subject"] = alert.subject
    msg["From"] = formataddr((FROM_NAME, settings.username))
    msg["To"] = settings.to
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=NEUTRAL_HOST)
    if alert.severity == "high":
        msg["X-Priority"] = "1"
        msg["Importance"] = "High"
    msg.set_content(alert.text)
    msg.add_alternative(alert.html, subtype="html")
    return msg


class EmailSender:
    name = "email"

    def __init__(self, settings: EmailSettings, timeout: float = 30.0):
        self.settings = settings
        self.timeout = timeout

    def send(self, message: OutgoingAlert) -> None:
        st = self.settings
        msg = build_message(st, message)
        try:
            with smtplib.SMTP(
                st.host, st.port, timeout=self.timeout, local_hostname=NEUTRAL_HOST
            ) as smtp:
                smtp.ehlo()
                smtp.starttls(context=ssl.create_default_context())
                smtp.ehlo()
                smtp.login(st.username, st.app_password)
                smtp.send_message(msg)
        except smtplib.SMTPAuthenticationError as exc:
            raise SendError(
                "Gmail rejected the sign-in. Check username and app_password in config.toml "
                "(the app password, not your Google password), and that 2-Step Verification is on."
            ) from exc
        except smtplib.SMTPRecipientsRefused as exc:
            raise SendError(f"Gmail refused the recipient address ({st.masked_to}).") from exc
        except (TimeoutError, smtplib.SMTPException, OSError, ssl.SSLError) as exc:
            # str(exc) from smtplib never contains the password.
            raise SendError(
                f"Couldn't send through {st.host}:{st.port}: {type(exc).__name__}: {exc}"
            ) from exc
