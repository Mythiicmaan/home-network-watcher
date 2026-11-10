"""Alert delivery: once per event, failures recorded and retried, never silent."""

from datetime import timedelta

from netwatch.alerts.base import SUBJECT_PREFIX, AlertSender, OutgoingAlert, SendError
from netwatch.alerts.dispatch import deliver_pending, delivery_status, next_delay
from netwatch.alerts.render import render_alert
from netwatch.services.common import create_alert
from tests.conftest import T0

BASE = "http://localhost:8766"


class RecordingSender:
    name = "test"

    def __init__(self, fail_times=0, crash=False):
        self.fail_times = fail_times
        self.crash = crash
        self.sent: list[OutgoingAlert] = []

    def send(self, message):
        if self.crash:
            raise RuntimeError("bug")
        if self.fail_times:
            self.fail_times -= 1
            raise SendError("SMTP timed out")
        self.sent.append(message)


def make(s, key="new_device:x", severity="warning"):
    return create_alert(
        s,
        kind="new_device",
        dedup_key=key,
        title="New device joined: Example",
        message="A new device.\n\nMark it Known.",
        severity=severity,
        facts=[("IP address", "192.0.2.90")],
        now=T0,
    )


def test_sender_protocol():
    assert isinstance(RecordingSender(), AlertSender)


def test_dedup_key_makes_alerts_once_per_event(s):
    assert make(s) is not None
    assert make(s) is None


def test_render_has_prefix_link_and_escaped_html(s):
    a = make(s)
    a.title = "New device joined: <script>"
    a.device_id = 7
    msg = render_alert(a, BASE)
    assert msg.subject.startswith(SUBJECT_PREFIX)
    assert f"{BASE}/devices/7" in msg.text
    assert "<script>" not in msg.html and "&lt;script&gt;" in msg.html
    assert "192.0.2.90" in msg.text


def test_high_priority_subject(s):
    a = make(s, severity="high")
    assert "HIGH PRIORITY" in render_alert(a, BASE).subject


def test_delivers_once(s):
    make(s)
    sender = RecordingSender()
    r = deliver_pending(s, [sender], T0, base_url=BASE)
    assert len(r.sent) == 1 and len(sender.sent) == 1
    r2 = deliver_pending(s, [sender], T0 + timedelta(minutes=5), base_url=BASE)
    assert r2.sent == [] and len(sender.sent) == 1


def test_failure_is_recorded_and_retried_with_backoff(s):
    a = make(s)
    sender = RecordingSender(fail_times=2)
    r = deliver_pending(s, [sender], T0, base_url=BASE)
    assert r.failed == [a.id]
    assert a.send_attempts == 1 and "SMTP timed out" in a.last_error
    assert a.next_attempt_at == T0 + next_delay(1)
    st = delivery_status(s, channel_configured=True)
    assert st.failing == 1 and "failed to send" in st.problem
    # Not retried before the backoff expires.
    assert deliver_pending(s, [sender], T0 + timedelta(seconds=30), base_url=BASE).failed == []
    # Retried after it: fails again, waits longer.
    t2 = T0 + timedelta(minutes=2)
    deliver_pending(s, [sender], t2, base_url=BASE)
    assert a.send_attempts == 2 and a.next_attempt_at == t2 + next_delay(2)
    # Third try works.
    t3 = t2 + timedelta(hours=1)
    r3 = deliver_pending(s, [sender], t3, base_url=BASE)
    assert r3.sent == [a.id] and a.sent_ok and a.sent_at == t3
    assert delivery_status(s, channel_configured=True).problem == ""


def test_backoff_caps_at_an_hour():
    assert next_delay(1) == timedelta(minutes=1)
    assert next_delay(50) == timedelta(hours=1)


def test_crashing_sender_is_contained(s):
    a = make(s)
    r = deliver_pending(s, [RecordingSender(crash=True), RecordingSender()], T0, base_url=BASE)
    assert r.sent == [a.id]
    assert "unexpected error" in a.last_error  # partial failure stays visible


def test_no_channel_is_loud_not_silent(s):
    make(s)
    r = deliver_pending(s, [], T0, base_url=BASE)
    assert r.no_channel
    st = delivery_status(s, channel_configured=False)
    assert st.unsent == 1 and "no alert channel" in st.problem


def test_quiet_hours_hold_all_but_high_priority(s):
    make(s, key="a")
    high = make(s, key="b", severity="high")
    sender = RecordingSender()
    r = deliver_pending(s, [sender], T0, base_url=BASE, quiet=True)
    assert r.sent == [high.id] and r.held_for_quiet_hours == 1
    r2 = deliver_pending(s, [sender], T0 + timedelta(hours=8), base_url=BASE)
    assert len(r2.sent) == 1


# ---------------------------------------------------------------- summary emails


def test_several_waiting_alerts_go_as_one_summary(s):
    a1 = make(s, key="new_device:a")
    a2 = make(s, key="new_device:b")
    a3 = create_alert(
        s,
        kind="risky_port",
        dedup_key="risky_port:1:23",
        title="Risky port open on TV: 23",
        message="m",
        severity="warning",
        now=T0,
    )
    sender = RecordingSender()
    r = deliver_pending(s, [sender], T0, base_url=BASE)
    assert sorted(r.sent) == sorted([a1.id, a2.id, a3.id])
    [msg] = sender.sent
    assert msg.subject == f"{SUBJECT_PREFIX} 3 alerts: 2 new devices, 1 risky port"
    assert "Risky port open on TV: 23" in msg.text and "New device joined" in msg.html
    assert all(a.sent_ok for a in (a1, a2, a3))


def test_high_priority_and_digest_are_never_folded_into_a_summary(s):
    make(s, key="a")
    make(s, key="b")
    high = make(s, key="gw", severity="high")
    digest = create_alert(
        s, kind="digest", dedup_key="digest:x", title="Weekly", message="m", now=T0
    )
    sender = RecordingSender()
    deliver_pending(s, [sender], T0, base_url=BASE)
    subjects = [m.subject for m in sender.sent]
    assert len(subjects) == 3
    assert any("HIGH PRIORITY" in x for x in subjects)
    assert any("Weekly" in x for x in subjects)
    assert any("2 alerts" in x for x in subjects)
    assert high.sent_ok and digest.sent_ok


def test_single_waiting_alert_is_sent_normally(s):
    make(s)
    sender = RecordingSender()
    deliver_pending(s, [sender], T0, base_url=BASE)
    assert sender.sent[0].subject == f"{SUBJECT_PREFIX} New device joined: Example"


def test_failed_summary_marks_every_alert_for_retry(s):
    a1, a2 = make(s, key="a"), make(s, key="b")
    r = deliver_pending(s, [RecordingSender(fail_times=1)], T0, base_url=BASE)
    assert sorted(r.failed) == sorted([a1.id, a2.id])
    assert a1.next_attempt_at == a2.next_attempt_at == T0 + next_delay(1)
    assert "SMTP timed out" in a1.last_error
