"""Shared web helpers: templates, DB session dependency, toasts, banners, formatting."""

from __future__ import annotations

import base64
import json
from collections.abc import Iterator
from datetime import datetime

from fastapi import Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from netwatch.db import PACKAGE_DIR
from netwatch.netutil import mask_mac
from netwatch.timeutil import to_local, utcnow

templates = Jinja2Templates(directory=str(PACKAGE_DIR / "templates"))
TOAST_COOKIE = "nw_toast"


def _local(dt: datetime | None, fmt: str = "short") -> str:
    lt = to_local(dt)
    if lt is None:
        return "never"
    time_s = lt.strftime("%I:%M %p").lstrip("0")
    if fmt == "time":
        return time_s
    today = to_local(utcnow()).date()
    if lt.date() == today:
        return f"today {time_s}"
    if (today - lt.date()).days == 1:
        return f"yesterday {time_s}"
    return f"{lt.strftime('%a')} {lt.month}/{lt.day} {time_s}"


def _ago(dt: datetime | None) -> str:
    if dt is None:
        return "never"
    secs = int((utcnow() - dt).total_seconds())
    if secs < 60:
        return "just now"
    if secs < 3600:
        return f"{secs // 60} min ago"
    if secs < 86400:
        return f"{secs // 3600} h ago"
    return f"{secs // 86400} d ago"


templates.env.filters["local"] = _local
templates.env.filters["ago"] = _ago
templates.env.filters["mask_mac"] = mask_mac


def get_db(request: Request) -> Iterator[Session]:
    factory = request.app.state.sessionmaker
    s = factory()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()


def _encode_toast(data: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).decode()


def _decode_toast(value: str | None) -> dict | None:
    if not value:
        return None
    try:
        data = json.loads(base64.urlsafe_b64decode(value.encode()).decode())
    except (ValueError, UnicodeDecodeError):
        return None
    return data if isinstance(data, dict) else None


def redirect(url: str, toast: str | None = None, *, error: bool = False) -> RedirectResponse:
    resp = RedirectResponse(url, status_code=303)
    if toast:
        resp.set_cookie(
            TOAST_COOKIE,
            _encode_toast({"msg": toast, "error": error}),
            max_age=60,
            httponly=True,
            samesite="lax",
        )
    return resp


def back_url(request: Request, default: str = "/") -> str:
    """Same-site path to return to after a form post."""
    ref = request.headers.get("referer") or ""
    host = request.headers.get("host") or ""
    if ref and host and f"//{host}" in ref:
        path = ref.split(f"//{host}", 1)[1]
        if path.startswith("/") and not path.startswith("//"):
            return path
    return default


def banners(request: Request, s: Session) -> list[dict]:
    """Problems that must never be silent: degraded scans, undelivered alerts, monitor errors."""
    from netwatch.alerts.dispatch import delivery_status, senders_from_config
    from netwatch.services import reports

    out = []
    app = request.app
    last = reports.last_scan(s)
    if last is not None and last.degraded:
        out.append({"level": "warn", "text": last.error or "Scan degraded: is a VPN connected?"})
    elif last is not None and not last.ok:
        out.append({"level": "bad", "text": f"Last scan failed: {last.error}"})
    channel = bool(senders_from_config(app.state.config))
    status = delivery_status(s, channel)
    if status.problem:
        out.append(
            {
                "level": "bad" if status.failing else "warn",
                "text": status.problem,
                "href": "/settings#alerts",
            }
        )
    monitor = getattr(app.state, "monitor", None)
    if monitor is not None and monitor.state.last_error:
        out.append({"level": "bad", "text": f"Monitor error: {monitor.state.last_error}"})
    if getattr(app.state, "sample_mode", False):
        out.append({"level": "info", "text": "Demo mode: fake sample network, no scanning."})
    return out


def render(request: Request, name: str, ctx: dict | None = None, status_code: int = 200):
    ctx = dict(ctx or {})
    s: Session | None = ctx.pop("s", None)
    context = {
        "request": request,
        "toast": _decode_toast(request.cookies.get(TOAST_COOKIE)),
        "nav": name.split(".")[0],
        "banners": banners(request, s) if s is not None else [],
        "monitor": getattr(request.app.state, "monitor", None),
    }
    context.update(ctx)
    resp = templates.TemplateResponse(request, name, context, status_code=status_code)
    if context["toast"]:
        resp.delete_cookie(TOAST_COOKIE)
    return resp


def checkbox(value: str | None) -> bool:
    return value in ("on", "true", "1", "yes")
