"""Turn an Alert row into a plain-text + simple HTML message."""

from __future__ import annotations

from html import escape

from netwatch.alerts.base import SUBJECT_PREFIX, OutgoingAlert
from netwatch.models import Alert


def render_alert(alert: Alert, base_url: str) -> OutgoingAlert:
    link = f"{base_url}/devices/{alert.device_id}" if alert.device_id else f"{base_url}/alerts"
    marker = "HIGH PRIORITY: " if alert.severity == "high" else ""
    subject = f"{SUBJECT_PREFIX} {marker}{alert.title}"
    lines = [alert.title, "", alert.message.strip(), ""]
    details = alert.details or {}
    for key, value in details.get("facts", []):
        lines.append(f"{key}: {value}")
    lines += ["", f"Open: {link}"]
    text = "\n".join(lines).strip() + "\n"

    facts = "".join(
        f"<tr><td style='color:#64748b;padding:2px 12px 2px 0'>{escape(str(k))}</td>"
        f"<td>{escape(str(v))}</td></tr>"
        for k, v in details.get("facts", [])
    )
    color = {"high": "#b91c1c", "warning": "#b45309"}.get(alert.severity, "#0f172a")
    paragraphs = "".join(f"<p>{escape(p)}</p>" for p in alert.message.strip().split("\n\n") if p)
    html = (
        "<div style='font-family:Segoe UI,Arial,sans-serif;font-size:15px;color:#0f172a'>"
        f"<h2 style='color:{color};font-size:18px'>{escape(marker + alert.title)}</h2>"
        f"{paragraphs}"
        f"<table style='font-size:14px'>{facts}</table>"
        f"<p><a href='{escape(link)}'>Open in Home Network Watcher</a></p>"
        "</div>"
    )
    return OutgoingAlert(subject=subject, text=text, html=html, severity=alert.severity)
