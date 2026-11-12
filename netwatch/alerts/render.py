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


KIND_NOUNS = {
    "new_device": ("new device", "new devices"),
    "risky_port": ("risky port", "risky ports"),
    "ip_conflict": ("IP conflict", "IP conflicts"),
    "gateway_mac_change": ("gateway change", "gateway changes"),
    "digest": ("digest", "digests"),
    "backup_failed": ("failed backup", "failed backups"),
}


def render_summary(alerts: list[Alert], base_url: str) -> OutgoingAlert:
    """Several waiting alerts in one email (e.g. everything that piled up overnight)."""
    counts: dict[str, int] = {}
    for a in alerts:
        counts[a.kind] = counts.get(a.kind, 0) + 1
    parts = []
    for kind, n in counts.items():
        one, many = KIND_NOUNS.get(kind, (kind, kind))
        parts.append(f"{n} {one if n == 1 else many}")
    subject = f"{SUBJECT_PREFIX} {len(alerts)} alerts: {', '.join(parts)}"

    text_blocks, html_blocks = [], []
    for a in alerts:
        link = f"{base_url}/devices/{a.device_id}" if a.device_id else f"{base_url}/alerts"
        facts = (a.details or {}).get("facts", [])
        text_blocks.append(
            "\n".join(
                [f"* {a.title}"] + [f"    {k}: {v}" for k, v in facts] + [f"    Open: {link}"]
            )
        )
        rows = "".join(
            f"<tr><td style='color:#64748b;padding:1px 12px 1px 0'>{escape(str(k))}</td>"
            f"<td>{escape(str(v))}</td></tr>"
            for k, v in facts
        )
        color = {"high": "#b91c1c", "warning": "#b45309"}.get(a.severity, "#0f172a")
        html_blocks.append(
            f"<h3 style='color:{color};font-size:16px;margin:18px 0 4px'>{escape(a.title)}</h3>"
            f"<table style='font-size:14px'>{rows}</table>"
            f"<p style='margin:4px 0'><a href='{escape(link)}'>Open</a></p>"
        )
    intro = f"{len(alerts)} alerts were waiting, so they're sent together in one email."
    text = intro + "\n\n" + "\n\n".join(text_blocks) + f"\n\nAll alerts: {base_url}/alerts\n"
    html = (
        "<div style='font-family:Segoe UI,Arial,sans-serif;font-size:15px;color:#0f172a'>"
        f"<p>{escape(intro)}</p>{''.join(html_blocks)}"
        f"<p><a href='{escape(base_url)}/alerts'>All alerts in Home Network Watcher</a></p></div>"
    )
    severity = "high" if any(a.severity == "high" for a in alerts) else "warning"
    return OutgoingAlert(subject=subject, text=text, html=html, severity=severity)
