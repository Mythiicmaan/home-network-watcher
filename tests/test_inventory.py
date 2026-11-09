"""Applying simulated scans to the database: baseline, new devices, degraded scans,
gateway MAC changes, IP conflicts, and port-check alerts. Each alert fires once."""

from datetime import timedelta

from sqlalchemy import func, select

from netwatch.models import Alert, Device, PortScan, ScanRun, Sighting
from netwatch.ports import PortResult
from netwatch.services import inventory, portcheck, reports
from netwatch.services.common import GATEWAY_MAC_KEY, get_setting
from tests.conftest import EVIL_MAC, GW_MAC, HOME, T0, VENDORS, scan

STEP = timedelta(minutes=5)


def apply(s, ip_to_mac, at, **kw):
    r = inventory.apply_discovery(s, scan(ip_to_mac, at, **kw), vendors=VENDORS, now=at)
    s.commit()
    return r


def alerts(s, kind=None):
    q = select(Alert)
    if kind:
        q = q.where(Alert.kind == kind)
    return list(s.scalars(q.order_by(Alert.id)))


def warm_up(s, n=3):
    """Baseline plus a few normal scans so 'usual device count' is known."""
    for i in range(n):
        apply(s, HOME, T0 + i * STEP)
    return T0 + n * STEP


def test_first_scan_is_a_silent_baseline(s):
    r = apply(s, HOME, T0)
    assert r.baseline and r.health.ok and not r.health.degraded
    assert len(r.new_device_ids) == len(HOME)
    assert alerts(s) == []  # no flood of "new device" alerts on day one
    assert get_setting(s, GATEWAY_MAC_KEY) == GW_MAC
    gw = s.scalar(select(Device).where(Device.mac == GW_MAC))
    assert gw.is_gateway and gw.vendor == "Example Gateways Inc."
    assert all(d.in_baseline for d in s.scalars(select(Device)))
    # Baseline devices still get one port check each.
    assert s.scalar(select(func.count()).select_from(PortScan)) == len(HOME)


def test_new_device_alerts_exactly_once(s):
    t = warm_up(s)
    laptop = {**HOME, "192.0.2.90": "02:00:00:00:09:01"}
    r = apply(s, laptop, t)
    assert len(r.new_device_ids) == 1
    [a] = alerts(s, "new_device")
    assert a.dedup_key == "new_device:02:00:00:00:09:01"
    assert "192.0.2.90" in str(a.details)
    assert not a.sent_ok
    # Seen again in the next scans: no repeat alert.
    apply(s, laptop, t + STEP)
    apply(s, laptop, t + 2 * STEP)
    assert len(alerts(s, "new_device")) == 1
    # A port check was queued for it.
    dev = s.get(Device, r.new_device_ids[0])
    assert s.scalar(select(PortScan).where(PortScan.device_id == dev.id)).reason == "new"


def test_randomized_mac_is_flagged(s):
    t = warm_up(s)
    r = apply(s, {**HOME, "192.0.2.91": "02:00:00:00:09:02"}, t)
    assert s.get(Device, r.new_device_ids[0]).is_randomized_mac  # 02:... is locally administered


def test_degraded_scan_never_alerts_or_adds_devices(s):
    t = warm_up(s)
    # A VPN connects: only the PC and one other device are visible, gateway missing.
    few = {k: v for k, v in list(HOME.items())[1:3]} | {"192.0.2.95": "02:00:00:00:09:05"}
    r = apply(s, few, t, vpn_up=["NordLynx (NordLynx Tunnel)"])
    assert r.health.degraded
    assert "NordLynx" in r.health.reason
    run = s.get(ScanRun, r.scan_run_id)
    assert run.ok and run.degraded
    assert alerts(s) == []
    assert s.scalar(select(Device).where(Device.mac == "02:00:00:00:09:05")) is None
    # Nobody looks offline: the online window only counts good scans.
    assert len(reports.online_ids(s)) == len(HOME)


def test_degraded_scan_after_good_history_keeps_online_status(s):
    t = warm_up(s)
    for i in range(3):
        apply(s, {}, t + i * STEP)  # nothing found at all
    assert len(reports.online_ids(s)) == len(HOME)


def test_failed_scan_is_recorded(s):
    r = inventory.apply_discovery(
        s, scan({}, T0, error="Discovery failed: boom"), vendors=VENDORS, now=T0
    )
    run = s.get(ScanRun, r.scan_run_id)
    assert not run.ok and "boom" in run.error
    assert alerts(s) == []


def test_device_goes_offline_after_two_good_scans(s):
    t = warm_up(s)
    tv_mac = HOME["192.0.2.30"]
    without_tv = {k: v for k, v in HOME.items() if v != tv_mac}
    apply(s, without_tv, t)
    tv = s.scalar(select(Device).where(Device.mac == tv_mac))
    assert tv.id in reports.online_ids(s)  # missed one scan: still online
    apply(s, without_tv, t + STEP)
    assert tv.id not in reports.online_ids(s)


def test_gateway_mac_change_alerts_once_with_high_priority(s):
    t = warm_up(s)
    spoofed = {**HOME, "192.0.2.1": EVIL_MAC, "192.0.2.66": EVIL_MAC}
    apply(s, spoofed, t)
    apply(s, spoofed, t + STEP)
    [a] = alerts(s, "gateway_mac_change")
    assert a.severity == "high"
    assert "T1557.002" in a.message
    assert ["Same MAC also answers for", "192.0.2.66"] in a.details["facts"]
    # The trusted MAC is NOT silently replaced.
    assert get_setting(s, GATEWAY_MAC_KEY) == GW_MAC
    # Back to normal: no new alert.
    apply(s, HOME, t + 2 * STEP)
    assert len(alerts(s, "gateway_mac_change")) == 1


def test_accepting_a_new_gateway_stops_alerts(s):
    t = warm_up(s)
    new_router = {**HOME, "192.0.2.1": "02:00:00:00:00:02"}
    apply(s, new_router, t)
    assert len(alerts(s, "gateway_mac_change")) == 1
    inventory.accept_gateway_mac(s, "02:00:00:00:00:02")
    apply(s, new_router, t + STEP)
    assert len(alerts(s, "gateway_mac_change")) == 1


def test_ip_conflict_detected_from_flip_flopping(s):
    t = warm_up(s)
    a_mac = HOME["192.0.2.50"]
    b_mac = "02:00:00:00:0c:01"
    with_b = {**{k: v for k, v in HOME.items() if k != "192.0.2.50"}, "192.0.2.50": b_mac}
    apply(s, with_b, t)  # B takes the printer's IP
    assert alerts(s, "ip_conflict") == []  # one change alone looks like DHCP reuse
    apply(s, HOME, t + STEP)  # ...and A answers again
    [a] = alerts(s, "ip_conflict")
    assert a.details["macs"] == sorted([a_mac, b_mac])
    apply(s, with_b, t + 2 * STEP)
    apply(s, HOME, t + 3 * STEP)
    assert len(alerts(s, "ip_conflict")) == 1


def test_sightings_record_each_scan(s):
    warm_up(s, 2)
    assert s.scalar(select(func.count()).select_from(Sighting)) == 2 * len(HOME)


# ---------------------------------------------------------------- port checks


def _run_check(s, device, ports, now):
    pscan = s.scalar(
        select(PortScan).where(PortScan.device_id == device.id, PortScan.status == "queued")
    )
    portcheck.start(s, pscan, now)
    ids = portcheck.finish(
        s, pscan, PortResult("nmap", [{"port": p, "service": ""} for p in ports]), now
    )
    s.commit()
    return pscan, ids


def test_risky_ports_alert_once_per_device_and_port(s):
    t = warm_up(s)
    r = apply(s, {**HOME, "192.0.2.92": "02:00:00:00:09:03"}, t)
    dev = s.get(Device, r.new_device_ids[0])
    pscan, ids = _run_check(s, dev, [22, 23, 80], t)
    assert pscan.status == "done"
    assert [f["port"] for f in pscan.risky_ports] == [23, 80]
    assert len(ids) == 2
    telnet = s.scalar(select(Alert).where(Alert.dedup_key == f"risky_port:{dev.id}:23"))
    assert telnet.severity == "high" and "Telnet" in telnet.title
    # A manual re-check finds the same ports: no repeat alerts.
    inventory.queue_port_scan(s, dev, "manual")
    _, ids2 = _run_check(s, dev, [23, 80], t + STEP)
    assert ids2 == []


def test_ignored_devices_never_alert(s):
    t = warm_up(s)
    plug = s.scalar(select(Device).where(Device.mac == HOME["192.0.2.60"]))
    plug.status = "ignored"
    s.commit()
    _, ids = _run_check(s, plug, [23], t)
    assert ids == []


def test_port_queue_does_not_double_queue(s):
    warm_up(s, 1)
    dev = s.scalar(select(Device).where(Device.mac == GW_MAC))
    assert inventory.queue_port_scan(s, dev, "manual") is None  # baseline check still queued


def test_interrupted_checks_are_requeued(s):
    warm_up(s, 1)
    pscan = portcheck.next_queued(s)
    portcheck.start(s, pscan, T0)
    assert portcheck.recover_interrupted(s) == 1
    s.refresh(pscan)
    assert pscan.status == "queued"


def test_failed_port_check_is_recorded(s):
    warm_up(s, 1)
    pscan = portcheck.next_queued(s)
    portcheck.start(s, pscan, T0)
    portcheck.finish(s, pscan, PortResult("nmap", error="Nmap failed: x"), T0)
    assert pscan.status == "failed" and "Nmap failed" in pscan.error
