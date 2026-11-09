"""Sign-in, settings, scan now, CSV export, JSON API, health, and home-screen icons."""

from __future__ import annotations

import csv
import io
import math
import struct
import zlib
from datetime import timedelta

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from netwatch import auth
from netwatch.alerts.dispatch import delivery_status, senders_from_config
from netwatch.models import Alert, Device
from netwatch.services import inventory, reports
from netwatch.services.common import (
    GATEWAY_IP_KEY,
    GATEWAY_MAC_KEY,
    OUI_PROBLEM_KEY,
    NetwatchError,
    get_setting,
)
from netwatch.timeutil import to_local, utcnow
from netwatch.web.common import get_db, redirect, render

router = APIRouter()


# ---------------------------------------------------------------- sign-in


def _safe_next(url: str | None) -> str:
    if url and url.startswith("/") and not url.startswith("//"):
        return url
    return "/"


@router.get("/login")
def login_page(request: Request, next: str = "/", s: Session = Depends(get_db)):
    limiter: auth.RateLimiter = request.app.state.limiter
    return render(
        request,
        "login.html",
        {
            "next": _safe_next(next),
            "locked_for": limiter.seconds_locked(),
            "pin_set": auth.pin_is_set(s),
        },
    )


@router.post("/login")
def login(
    request: Request, pin: str = Form(""), next: str = Form("/"), s: Session = Depends(get_db)
):
    limiter: auth.RateLimiter = request.app.state.limiter
    if limiter.seconds_locked():
        return redirect(
            f"/login?next={_safe_next(next)}", "Too many tries. Wait a few minutes.", error=True
        )
    if not auth.verify_pin(get_setting(s, auth.PIN_HASH_KEY), pin):
        limiter.record_failure()
        return redirect(f"/login?next={_safe_next(next)}", "Wrong PIN", error=True)
    limiter.reset()
    cfg = request.app.state.config
    resp = redirect(_safe_next(next))
    https = request.headers.get("x-forwarded-proto") == "https" or request.url.scheme == "https"
    resp.set_cookie(
        auth.COOKIE_NAME,
        auth.make_session_cookie(request.app.state.auth_secret, cfg.session_days),
        max_age=cfg.session_days * 86400,
        httponly=True,
        samesite="lax",
        secure=https,
    )
    return resp


@router.post("/logout")
def logout():
    resp = redirect("/login", "Signed out")
    resp.delete_cookie(auth.COOKIE_NAME)
    return resp


# ---------------------------------------------------------------- settings


@router.get("/settings")
def settings_page(request: Request, s: Session = Depends(get_db)):
    cfg = request.app.state.config
    monitor = request.app.state.monitor
    last = reports.last_scan(s)
    result = monitor.state.last_result if monitor else None
    trusted = get_setting(s, GATEWAY_MAC_KEY)
    pending_gw = s.scalar(
        select(Alert)
        .where(Alert.kind == "gateway_mac_change", Alert.acknowledged.is_(False))
        .order_by(Alert.id.desc())
        .limit(1)
    )
    channel = bool(senders_from_config(cfg))
    return render(
        request,
        "settings.html",
        {
            "s": s,
            "cfg": cfg,
            "last": last,
            "result": result,
            "trusted_gw": trusted,
            "gateway_ip": get_setting(s, GATEWAY_IP_KEY),
            "pending_gw": pending_gw,
            "delivery": delivery_status(s, channel),
            "channel": channel,
            "oui_entries": len(monitor.vendors) if monitor else None,
            "oui_problem": get_setting(s, OUI_PROBLEM_KEY) or "",
            "pin_set": auth.pin_is_set(s),
            "is_local": request.state.is_local,
            "device_count": len(list(s.scalars(select(Device.id)))),
        },
    )


@router.post("/settings/pin")
def settings_pin(
    request: Request, pin: str = Form(""), pin2: str = Form(""), s: Session = Depends(get_db)
):
    if not request.state.is_local:
        raise NetwatchError("For safety, the PIN can only be changed on the home PC itself.")
    if pin != pin2:
        raise NetwatchError("The two PINs don't match.")
    try:
        auth.set_pin(s, pin)
    except ValueError as exc:
        raise NetwatchError(str(exc)) from exc
    s.flush()
    request.app.state.refresh_auth(s)
    return redirect("/settings#pin", "PIN saved. Phones will need to sign in again.")


@router.post("/scan-now")
def scan_now(request: Request):
    monitor = request.app.state.monitor
    if monitor is None:
        raise NetwatchError("The monitor isn't running (demo mode or scanning turned off).")
    monitor.request_scan()
    return redirect("/", "Scan started. Results in about 20 seconds.")


@router.post("/settings/accept-gateway")
def accept_gateway(request: Request, alert_id: int = Form(...), s: Session = Depends(get_db)):
    """Owner confirms the gateway really changed (e.g. a new or reset router)."""
    a = s.get(Alert, alert_id)
    if a is None or a.kind != "gateway_mac_change":
        raise NetwatchError("That alert doesn't exist.")
    new_mac = (a.details or {}).get("observed_mac")
    if not new_mac:
        raise NetwatchError("This alert doesn't say which MAC to trust.")
    inventory.accept_gateway_mac(s, new_mac)
    a.acknowledged, a.acknowledged_at = True, utcnow()
    return redirect("/settings#gateway", "New gateway MAC trusted.")


# ---------------------------------------------------------------- export and API

EXPORT_COLUMNS = [
    "friendly_name",
    "owner",
    "status",
    "vendor",
    "hostname",
    "last_ip",
    "mac",
    "randomized_mac",
    "first_seen_local",
    "last_seen_local",
    "notes",
]


@router.get("/export.csv")
def export_csv(s: Session = Depends(get_db)):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(EXPORT_COLUMNS)
    for d in s.scalars(select(Device).order_by(Device.id)):
        w.writerow(
            [
                d.friendly_name,
                d.owner,
                d.status,
                d.vendor,
                d.hostname,
                d.last_ip,
                d.mac,
                "yes" if d.is_randomized_mac else "",
                to_local(d.first_seen).isoformat(timespec="minutes"),
                to_local(d.last_seen).isoformat(timespec="minutes"),
                d.notes,
            ]
        )
    stamp = to_local(utcnow()).date().isoformat()
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="devices-{stamp}.csv"'},
    )


@router.get("/api/summary")
def api_summary(s: Session = Depends(get_db)):
    """Read-only JSON for the future Family Command Center. No MACs or IPs."""
    now = utcnow()
    sm = reports.summary(s, now)
    new = list(
        s.scalars(
            select(Device)
            .where(Device.first_seen >= now - timedelta(days=7))
            .order_by(Device.first_seen.desc())
        )
    )
    last = sm.last_scan
    return {
        "devices": sm.devices,
        "online": sm.online,
        "unknown": sm.unknown,
        "unacknowledged_alerts": sm.unacknowledged,
        "new_devices_7d": [
            {
                "id": d.id,
                "name": d.display_name,
                "status": d.status,
                "first_seen": d.first_seen.isoformat() + "Z",
            }
            for d in new
        ],
        "last_alert": (
            {
                "kind": sm.last_alert.kind,
                "title": sm.last_alert.title,
                "severity": sm.last_alert.severity,
                "created_at": sm.last_alert.created_at.isoformat() + "Z",
            }
            if sm.last_alert
            else None
        ),
        "last_scan": (
            {
                "at": last.started_at.isoformat() + "Z",
                "ok": last.ok,
                "degraded": last.degraded,
                "devices_found": last.hosts_found,
            }
            if last
            else None
        ),
    }


@router.get("/health")
def health(request: Request, s: Session = Depends(get_db)):
    last = reports.last_scan(s)
    monitor = request.app.state.monitor
    channel = bool(senders_from_config(request.app.state.config))
    st = delivery_status(s, channel)
    return {
        "status": "ok",
        "monitor_running": bool(monitor and monitor.state.running),
        "last_scan": {
            "at": last.started_at.isoformat() + "Z",
            "ok": last.ok,
            "degraded": last.degraded,
        }
        if last
        else None,
        "alerts": {"channel_configured": channel, "unsent": st.unsent, "failing": st.failing},
    }


# ---------------------------------------------------------------- home screen


@router.get("/manifest.webmanifest")
def manifest():
    return JSONResponse(
        {
            "name": "Home Network Watcher",
            "short_name": "NetWatch",
            "start_url": "/",
            "display": "standalone",
            "background_color": "#0f172a",
            "theme_color": "#0f172a",
            "icons": [
                {"src": "/icon-192.png", "sizes": "192x192", "type": "image/png"},
                {"src": "/icon-512.png", "sizes": "512x512", "type": "image/png"},
            ],
        },
        media_type="application/manifest+json",
    )


def make_icon_png(size: int) -> bytes:
    """Draw the app icon (a radar: rings and a dot) as a PNG, so the repo holds no binaries."""
    bg, fg, dot = (15, 23, 42), (56, 189, 248), (34, 197, 94)
    c = (size - 1) / 2
    rows = []
    for y in range(size):
        row = bytearray([0])
        for x in range(size):
            r = math.hypot(x - c, y - c) / size
            color = bg
            if any(abs(r - ring) < 0.018 for ring in (0.16, 0.27, 0.38)):
                color = fg
            if r < 0.06:
                color = fg
            if math.hypot(x - c - size * 0.19, y - c + size * 0.17) / size < 0.045:
                color = dot
            row.extend(color)
        rows.append(bytes(row))
    raw = zlib.compress(b"".join(rows), 9)

    def chunk(tag: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + tag
            + data
            + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
        )

    header = struct.pack(">IIBBBBB", size, size, 8, 2, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", raw) + chunk(b"IEND", b"")


_ICONS: dict[int, bytes] = {}


def _icon(size: int) -> Response:
    if size not in _ICONS:
        _ICONS[size] = make_icon_png(size)
    return Response(
        _ICONS[size], media_type="image/png", headers={"Cache-Control": "public, max-age=86400"}
    )


@router.get("/apple-touch-icon.png")
def apple_icon():
    return _icon(180)


@router.get("/icon-192.png")
def icon_192():
    return _icon(192)


@router.get("/icon-512.png")
def icon_512():
    return _icon(512)


@router.get("/favicon.ico")
def favicon():
    return _icon(32)
