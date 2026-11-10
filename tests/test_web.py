"""End-to-end tests through the HTTP layer, on the FAKE sample network."""

from __future__ import annotations

import csv
import io
import ipaddress
import re

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from netwatch.app import create_app
from netwatch.config import Paths
from netwatch.models import Alert, Device, PortScan
from netwatch.sample_data import build_sample_db
from netwatch.services.common import create_alert
from netwatch.timeutil import utcnow

TS_CLIENT_IP = str(ipaddress.IPv4Network("100.64.0.0/10")[7])  # built at runtime


@pytest.fixture
def app(tmp_path):
    a = create_app(Paths(tmp_path), run_monitor=False, sample=True)
    return a


def local_client(app) -> TestClient:
    return TestClient(app, base_url="http://localhost:8766", client=("127.0.0.1", 50000))


def phone_client(app) -> TestClient:
    """Looks like a phone coming through `tailscale serve`."""
    c = TestClient(
        app, base_url="https://pc.example-tailnet" + ".ts.net", client=("127.0.0.1", 50001)
    )
    c.headers.update({"X-Forwarded-For": TS_CLIENT_IP, "X-Forwarded-Proto": "https"})
    return c


@pytest.fixture
def client(app):
    with local_client(app) as c:
        s = app.state.sessionmaker()
        build_sample_db(s, utcnow())
        s.commit()
        s.close()
        yield c


def db(app):
    return app.state.sessionmaker()


def device(app, name) -> Device:
    s = db(app)
    d = s.scalar(select(Device).where(Device.friendly_name == name))
    s.close()
    return d


# ---------------------------------------------------------------- pages


def test_dashboard_shows_health_unknowns_and_alerts(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "Scan health" in r.text
    assert "Needs a look" in r.text
    assert "Example IoT Modules" in r.text  # an unknown device is highlighted
    assert "Risky ports open" in r.text
    assert "Demo mode" in r.text


def test_status_partial(client):
    r = client.get("/partials/status")
    assert r.status_code == 200 and 'hx-get="/partials/status"' in r.text


def test_devices_list_search_sort_and_filter(client):
    r = client.get("/devices")
    assert r.status_code == 200
    assert "Living Room TV" in r.text and "Game Console" in r.text
    assert "02:00:00:••:••:01" in r.text  # MACs are masked by default...
    assert 'data-reveal="02:00:00:00:00:01"' in r.text  # ...and revealed on tap
    r = client.get("/devices", params={"q": "printer"})
    assert "Office Printer" in r.text and "Living Room TV" not in r.text
    r = client.get("/devices", params={"status": "unknown"})
    assert "Office Printer" not in r.text and "2 devices" in r.text
    r = client.get("/devices", params={"sort": "ip"})
    names = re.findall(r"<strong>([^<]+)</strong>", r.text)
    assert names.index("Gateway") < names.index("Office Printer")
    # HTMX search swaps only the rows.
    r = client.get(
        "/devices", params={"q": "tv"}, headers={"HX-Request": "true", "HX-Target": "device-rows"}
    )
    assert "<html" not in r.text and "Living Room TV" in r.text


def test_device_page_timeline_and_ports(client, app):
    d = device(app, "Office Printer")
    r = client.get(f"/devices/{d.id}")
    assert r.status_code == 200
    assert "Online, last 7 days" in r.text
    assert r.text.count('<i class="on"') > 0
    assert "Unencrypted web page" in r.text and "What to do" in r.text
    assert client.get("/devices/99999").status_code == 400


def test_this_pc_is_labeled_and_explains_its_port_check(client, app):
    d = device(app, "Home Desktop")
    r = client.get(f"/devices/{d.id}")
    assert "This PC (runs NetWatch)" in r.text
    assert "Windows Firewall doesn't apply" in r.text
    assert "This PC</span>" in client.get("/devices").text
    s = db(app)
    assert not s.scalars(
        select(Alert).where(Alert.device_id == d.id, Alert.kind == "risky_port")
    ).all()
    s.close()


def test_edit_device_and_mark_known(client, app):
    s = db(app)
    unknown = s.scalar(select(Device).where(Device.status == "unknown"))
    s.close()
    r = client.post(
        f"/devices/{unknown.id}",
        data={"friendly_name": "Kid Laptop", "owner": "Kids", "notes": "school", "status": "known"},
    )
    assert r.status_code == 200 and "Saved" in r.text
    s = db(app)
    d = s.get(Device, unknown.id)
    assert (d.friendly_name, d.owner, d.status) == ("Kid Laptop", "Kids", "known")
    # Its new-device alert is settled too.
    a = s.scalar(select(Alert).where(Alert.device_id == d.id, Alert.kind == "new_device"))
    assert a.acknowledged
    s.close()


def test_one_tap_known_with_name_from_dashboard(client, app):
    s = db(app)
    unknown = s.scalars(select(Device).where(Device.status == "unknown")).all()[-1]
    s.close()
    r = client.post(
        f"/devices/{unknown.id}/status",
        data={"status": "known", "friendly_name": "Sam's Tablet"},
        headers={"Referer": "http://localhost:8766/"},
    )
    assert r.status_code == 200 and "Marked Known" in r.text
    assert device(app, "Sam's Tablet").status == "known"


def test_ignore(client, app):
    d = device(app, "Doorbell")
    client.post(f"/devices/{d.id}/status", data={"status": "ignored"})
    assert device(app, "Doorbell").status == "ignored"
    r = client.post(f"/devices/{d.id}/status", data={"status": "bogus"})
    assert "Unknown status" in r.text


def test_scan_now_buttons_refuse_in_demo_mode(client, app):
    d = device(app, "Office Printer")
    r = client.post(f"/devices/{d.id}/scan")
    assert "Demo mode" in r.text
    r = client.post("/scan-now")
    assert "demo mode or scanning turned off" in r.text


def test_manual_port_check_queues_when_not_demo(tmp_path):
    a = create_app(Paths(tmp_path), run_monitor=False, sample=False)
    with local_client(a) as c:
        s = a.state.sessionmaker()
        build_sample_db(s, utcnow())
        s.commit()
        d = s.scalar(select(Device).where(Device.friendly_name == "Office Printer"))
        s.close()
        r = c.post(f"/devices/{d.id}/scan")
        assert "queued" in r.text.lower()
        s = a.state.sessionmaker()
        assert s.scalar(
            select(PortScan).where(PortScan.device_id == d.id, PortScan.status == "queued")
        )
        s.close()


def test_alerts_filter_and_acknowledge(client, app):
    r = client.get("/alerts")
    assert r.status_code == 200 and "New device joined" in r.text
    r = client.get("/alerts", params={"kind": "risky_port", "show": "all"})
    assert "Risky port open" in r.text and "New device joined" not in r.text
    s = db(app)
    a = s.scalar(select(Alert).where(Alert.acknowledged.is_(False)))
    s.close()
    client.post(f"/alerts/{a.id}/ack")
    s = db(app)
    assert s.get(Alert, a.id).acknowledged
    s.close()
    r = client.post("/alerts/ack-all", data={"kind": ""})
    assert "Acknowledged" in r.text
    s = db(app)
    assert s.scalar(select(Alert).where(Alert.acknowledged.is_(False))) is None
    s.close()


def test_undelivered_alerts_banner_is_loud(client):
    r = client.get("/")
    assert "no alert channel is set up yet" not in r.text  # sample alerts are all "sent"


def test_unsent_alert_shows_banner(client, app):
    s = db(app)
    create_alert(s, kind="new_device", dedup_key="x", title="New device joined: test", message="m")
    s.commit()
    s.close()
    assert "no alert channel is set up yet" in client.get("/").text


def test_gateway_change_can_be_accepted(client, app):
    s = db(app)
    a = create_alert(
        s,
        kind="gateway_mac_change",
        dedup_key="gw",
        title="Gateway MAC address changed (possible ARP spoofing)",
        message="m",
        severity="high",
        extra={"observed_mac": "02:00:00:00:00:02", "trusted_mac": "02:00:00:00:00:01"},
    )
    s.commit()
    aid = a.id
    s.close()
    r = client.get("/settings")
    assert "Trust the new MAC" in r.text
    client.post("/settings/accept-gateway", data={"alert_id": aid})
    from netwatch.services.common import GATEWAY_MAC_KEY, get_setting

    s = db(app)
    assert get_setting(s, GATEWAY_MAC_KEY) == "02:00:00:00:00:02"
    s.close()


def test_settings_page(client):
    r = client.get("/settings")
    assert r.status_code == 200
    assert "192.0.2.0/24" in r.text
    assert "Not set up yet" in r.text  # alert channel arrives in phase 3


def test_csv_export(client):
    r = client.get("/export.csv")
    assert r.headers["content-type"].startswith("text/csv")
    rows = list(csv.reader(io.StringIO(r.text)))
    assert rows[0][0] == "friendly_name" and len(rows) == 13


def test_api_summary_has_no_macs_or_ips(client):
    r = client.get("/api/summary")
    data = r.json()
    assert data["devices"] == 12 and data["unknown"] == 2
    assert data["last_scan"]["ok"] is True
    text = r.text
    assert "02:00:00" not in text and "192.0.2." not in text


def test_health_and_icons(client):
    assert client.get("/health").json()["status"] == "ok"
    r = client.get("/icon-192.png")
    assert r.content.startswith(b"\x89PNG")
    assert client.get("/manifest.webmanifest").json()["short_name"] == "NetWatch"


# ---------------------------------------------------------------- security


def test_security_headers(client):
    r = client.get("/")
    assert "script-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["cache-control"] == "no-store"


def test_bad_host_rejected(app):
    with TestClient(app, base_url="http://evil.example") as c:
        assert c.get("/").status_code == 400


def test_cross_site_post_blocked(client, app):
    d = device(app, "Doorbell")
    r = client.post(
        f"/devices/{d.id}/status",
        data={"status": "ignored"},
        headers={"Origin": "http://evil.example"},
    )
    assert r.status_code == 403


def test_phone_needs_pin(client, app):
    with phone_client(app) as phone:
        r = phone.get("/", follow_redirects=False)
        assert r.status_code == 403  # no PIN set yet
        assert phone.get("/api/summary").status_code == 401
    # Set a PIN from the desktop.
    r = client.post("/settings/pin", data={"pin": "2468", "pin2": "2468"})
    assert "PIN saved" in r.text
    with phone_client(app) as phone:
        r = phone.get("/devices", follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"].startswith("/login")
        r = phone.post("/login", data={"pin": "0000", "next": "/devices"})
        assert "Wrong PIN" in r.text
        r = phone.post("/login", data={"pin": "2468", "next": "/devices"}, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/devices"
        assert "secure" in r.headers["set-cookie"].lower()
        assert phone.get("/devices").status_code == 200
        # The PIN can't be changed from a phone.
        r = phone.post("/settings/pin", data={"pin": "1111", "pin2": "1111"})
        assert "only be changed on the home PC" in r.text


def test_login_page_is_public(app):
    with phone_client(app) as phone:
        assert phone.get("/login").status_code == 200


# ---------------------------------------------------------------- phase 3: email


EMAIL_TOML = """
[alerts.email]
smtp_host = "smtp.gmail.com"
smtp_port = 587
username = "alex.sample@gmail.com"
app_password = "abcd efgh ijkl mnop"
to = "alex.sample@gmail.com"
"""


def test_settings_shows_email_channel_and_test_button(tmp_path, monkeypatch):
    (tmp_path / "config.toml").write_text(EMAIL_TOML, encoding="utf-8")
    a = create_app(Paths(tmp_path), run_monitor=False, sample=True)
    sent = []
    monkeypatch.setattr(
        "netwatch.alerts.dispatch.send_test_alert", lambda cfg: (sent.append(1) or True, "")
    )
    with local_client(a) as c:
        r = c.get("/settings")
        assert "Email to a***@gmail.com" in r.text and "Send test alert" in r.text
        assert "abcd" not in r.text  # never shows the password
        r = c.post("/settings/test-alert")
        assert "Test alert sent" in r.text and sent == [1]


def test_test_alert_failure_is_loud(tmp_path, monkeypatch):
    (tmp_path / "config.toml").write_text(EMAIL_TOML, encoding="utf-8")
    a = create_app(Paths(tmp_path), run_monitor=False, sample=True)
    monkeypatch.setattr(
        "netwatch.alerts.dispatch.send_test_alert",
        lambda cfg: (False, "Gmail rejected the sign-in."),
    )
    with local_client(a) as c:
        r = c.post("/settings/test-alert")
        assert "Test alert FAILED" in r.text and 'class="toast error"' in r.text


def test_incomplete_email_settings_show_a_banner(tmp_path):
    (tmp_path / "config.toml").write_text(
        EMAIL_TOML.replace("alex.sample@gmail.com", "you@example.com"), encoding="utf-8"
    )
    a = create_app(Paths(tmp_path), run_monitor=False, sample=True)
    with local_client(a) as c:
        r = c.get("/")
        assert "Email settings in config.toml need fixing" in r.text
        assert "still the example address" in r.text
