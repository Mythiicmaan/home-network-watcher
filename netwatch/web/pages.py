"""Dashboard, devices, device page, and alerts."""

from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends, Form, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from netwatch.models import ALERT_KINDS, Alert, Device, PortScan, Sighting
from netwatch.ports import RISKY_PORTS
from netwatch.services import devices as devsvc
from netwatch.services import inventory, portcheck, reports
from netwatch.services.common import NetwatchError
from netwatch.timeutil import to_local, utcnow
from netwatch.web.common import back_url, get_db, redirect, render

router = APIRouter()

KIND_LABELS = {
    "new_device": "New device",
    "gateway_mac_change": "Gateway MAC changed",
    "ip_conflict": "IP conflict",
    "risky_port": "Risky port",
    "digest": "Weekly digest",
}


def _scan_health(s: Session) -> dict:
    last = reports.last_scan(s)
    good = reports.last_good_scan(s)
    if last is None:
        return {"level": "warn", "label": "No scans yet", "last": None, "good": None}
    if not last.ok:
        level, label = "bad", "Last scan failed"
    elif last.degraded:
        level, label = "warn", "Degraded"
    elif utcnow() - last.started_at > timedelta(minutes=20):
        level, label = "warn", "Stale: no scan in 20+ min"
    else:
        level, label = "good", "Healthy"
    return {"level": level, "label": label, "last": last, "good": good}


# ---------------------------------------------------------------- dashboard


@router.get("/")
def dashboard(request: Request, s: Session = Depends(get_db)):
    now = utcnow()
    online = reports.online_ids(s)
    sm = reports.summary(s, now)
    attention = list(
        s.scalars(
            select(Device)
            .where(Device.status == "unknown")
            .order_by(Device.first_seen.desc())
            .limit(10)
        )
    )
    recent = list(
        s.scalars(select(Alert).order_by(Alert.created_at.desc(), Alert.id.desc()).limit(6))
    )
    return render(
        request,
        "dashboard.html",
        {
            "s": s,
            "sm": sm,
            "online": online,
            "attention": attention,
            "recent": recent,
            "health": _scan_health(s),
            "returning": {d.id: n for d, n in reports.returning_unknowns(s, now)},
            "risky": reports.latest_risky(s),
            "kinds": KIND_LABELS,
        },
    )


@router.get("/partials/status")
def status_partial(request: Request, s: Session = Depends(get_db)):
    """Auto-refreshing scan-health strip on the dashboard (HTMX)."""
    sm = reports.summary(s, utcnow())
    return render(request, "_status.html", {"sm": sm, "health": _scan_health(s)})


# ---------------------------------------------------------------- devices


@router.get("/devices")
def devices_page(
    request: Request,
    q: str = "",
    status: str = "",
    sort: str = "online",
    desc: int = 0,
    s: Session = Depends(get_db),
):
    online = reports.online_ids(s)
    rows = devsvc.list_devices(s, online, q=q, status=status, sort=sort, reverse=bool(desc))
    ctx = {"s": s, "rows": rows, "q": q, "status": status, "sort": sort, "desc": desc}
    if request.headers.get("hx-request") and request.headers.get("hx-target") == "device-rows":
        return render(request, "_device_rows.html", ctx)
    return render(request, "devices.html", ctx)


@router.get("/devices/{device_id}")
def device_page(device_id: int, request: Request, s: Session = Depends(get_db)):
    d = devsvc.get_device(s, device_id)
    now = utcnow()
    timeline = reports.presence_timeline(s, d.id, now)
    # Group into local-time days: [(label, [(hour, seen), ...]), ...]
    # Each day has 24 slots so the hours line up; None = outside the 7-day window.
    days: dict[str, list] = {}
    for hour, seen in timeline:
        lt = to_local(hour)
        slots = days.setdefault(f"{lt.strftime('%a')} {lt.month}/{lt.day}", [None] * 24)
        slots[lt.hour] = seen
    ips = s.execute(
        select(Sighting.ip, func.max(Sighting.seen_at))
        .where(Sighting.device_id == d.id)
        .group_by(Sighting.ip)
        .order_by(func.max(Sighting.seen_at).desc())
        .limit(5)
    ).all()
    scans = list(
        s.scalars(
            select(PortScan).where(PortScan.device_id == d.id).order_by(PortScan.id.desc()).limit(5)
        )
    )
    pending = next((p for p in scans if p.status in ("queued", "running")), None)
    latest = portcheck.latest_result(s, d.id)
    alerts = list(
        s.scalars(select(Alert).where(Alert.device_id == d.id).order_by(Alert.id.desc()).limit(10))
    )
    return render(
        request,
        "device.html",
        {
            "s": s,
            "d": d,
            "online": d.id in reports.online_ids(s),
            "days": list(days.items()),
            "ips": ips,
            "latest": latest,
            "pending": pending,
            "history": scans,
            "alerts": alerts,
            "risky_info": RISKY_PORTS,
            "kinds": KIND_LABELS,
            "days_seen": reports.distinct_days_seen(s, d.id, now - timedelta(days=14)),
        },
    )


@router.post("/devices/{device_id}")
def device_save(
    device_id: int,
    friendly_name: str = Form(""),
    owner: str = Form(""),
    notes: str = Form(""),
    status: str = Form("unknown"),
    s: Session = Depends(get_db),
):
    d = devsvc.get_device(s, device_id)
    devsvc.update_device(s, d, friendly_name=friendly_name, owner=owner, notes=notes, status=status)
    return redirect(f"/devices/{d.id}", "Saved")


@router.post("/devices/{device_id}/status")
def device_status(
    device_id: int,
    request: Request,
    status: str = Form(...),
    friendly_name: str = Form(None),
    s: Session = Depends(get_db),
):
    """One-tap Known / Ignore (optionally with a name), from the dashboard or an alert."""
    d = devsvc.get_device(s, device_id)
    devsvc.update_device(s, d, friendly_name=friendly_name, status=status)
    label = {
        "known": "Marked Known",
        "ignored": "Ignored: no more alerts",
        "unknown": "Marked Unknown",
    }
    return redirect(back_url(request, f"/devices/{d.id}"), f"{d.display_name}: {label[status]}")


@router.post("/devices/{device_id}/scan")
def device_scan(device_id: int, request: Request, s: Session = Depends(get_db)):
    d = devsvc.get_device(s, device_id)
    if getattr(request.app.state, "sample_mode", False):
        raise NetwatchError("Demo mode: port checks are turned off.")
    job = inventory.queue_port_scan(s, d, "manual")
    monitor = request.app.state.monitor
    if monitor is not None:
        monitor.request_port_check()
    msg = "Port check queued. Results appear here in a minute or two."
    if job is None:
        msg = "A port check is already waiting or running for this device."
    elif monitor is None:
        msg = "Port check queued. It runs when the monitor is running."
    return redirect(f"/devices/{d.id}#ports", msg)


# ---------------------------------------------------------------- alerts


@router.get("/alerts")
def alerts_page(request: Request, kind: str = "", show: str = "open", s: Session = Depends(get_db)):
    q = select(Alert)
    if kind in ALERT_KINDS:
        q = q.where(Alert.kind == kind)
    if show == "open":
        q = q.where(Alert.acknowledged.is_(False))
    items = list(s.scalars(q.order_by(Alert.created_at.desc(), Alert.id.desc()).limit(300)))
    return render(
        request,
        "alerts.html",
        {"s": s, "items": items, "kind": kind, "show": show, "kinds": KIND_LABELS},
    )


@router.post("/alerts/{alert_id}/ack")
def alert_ack(alert_id: int, request: Request, s: Session = Depends(get_db)):
    a = s.get(Alert, alert_id)
    if a is None:
        raise NetwatchError("That alert doesn't exist.")
    a.acknowledged, a.acknowledged_at = True, utcnow()
    return redirect(back_url(request, "/alerts"), "Acknowledged")


@router.post("/alerts/ack-all")
def alert_ack_all(request: Request, kind: str = Form(""), s: Session = Depends(get_db)):
    q = select(Alert).where(Alert.acknowledged.is_(False))
    if kind in ALERT_KINDS:
        q = q.where(Alert.kind == kind)
    now = utcnow()
    n = 0
    for a in s.scalars(q):
        a.acknowledged, a.acknowledged_at = True, now
        n += 1
    return redirect(back_url(request, "/alerts"), f"Acknowledged {n} alert(s)")
