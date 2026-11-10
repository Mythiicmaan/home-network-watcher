"""Gmail sender against a fake SMTP server. No real email is sent."""

import smtplib

import pytest

from netwatch.alerts import email as email_mod
from netwatch.alerts.base import OutgoingAlert, SendError
from netwatch.alerts.dispatch import channel_problem, send_test_alert, senders_from_config
from netwatch.config import Config, Paths

PASSWORD = "abcdefghijklmnop"  # a made-up 16-letter app password
GOOD = {
    "smtp_host": "smtp.gmail.com",
    "smtp_port": 587,
    "username": "alex.sample@gmail.com",
    "app_password": "abcd efgh ijkl mnop",  # Google shows it with spaces
    "to": "alex.sample@gmail.com",
}


def cfg_with(email: dict | None, tmp_path) -> Config:
    raw = {"alerts": {"email": email}} if email is not None else {}
    return Config(paths=Paths(tmp_path), raw=raw)


class FakeSMTP:
    instances: list["FakeSMTP"] = []
    fail_login = False
    fail_send: Exception | None = None

    def __init__(self, host, port, timeout=None, local_hostname=None):
        self.host, self.port, self.local_hostname = host, port, local_hostname
        self.calls: list[str] = []
        self.sent = []
        FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.calls.append("quit")

    def ehlo(self):
        self.calls.append("ehlo")

    def starttls(self, context=None):
        assert context is not None
        self.calls.append("starttls")

    def login(self, user, password):
        self.calls.append("login")
        self.login_args = (user, password)
        if FakeSMTP.fail_login:
            raise smtplib.SMTPAuthenticationError(535, b"5.7.8 Username and Password not accepted")

    def send_message(self, msg):
        if FakeSMTP.fail_send:
            raise FakeSMTP.fail_send
        self.calls.append("send")
        self.sent.append(msg)


@pytest.fixture(autouse=True)
def fake_smtp(monkeypatch):
    FakeSMTP.instances = []
    FakeSMTP.fail_login = False
    FakeSMTP.fail_send = None
    monkeypatch.setattr(email_mod.smtplib, "SMTP", FakeSMTP)
    return FakeSMTP


def message(severity="warning"):
    return OutgoingAlert(
        "[NetWatch] New device joined: X", "plain body\n", "<p>html body</p>", severity
    )


# ---------------------------------------------------------------- settings


def test_no_section_means_not_set_up(tmp_path):
    cfg = cfg_with(None, tmp_path)
    assert email_mod.email_settings(cfg) == (None, "")
    assert senders_from_config(cfg) == []
    assert channel_problem(cfg) == ""


def test_good_settings_strip_spaces_from_password(tmp_path):
    st, problem = email_mod.email_settings(cfg_with(GOOD, tmp_path))
    assert problem == "" and st.app_password == PASSWORD and st.port == 587
    assert st.masked_to == "a***@gmail.com"


@pytest.mark.parametrize(
    "change, expected",
    [
        ({"username": "you@example.com"}, "username is still the example address"),
        ({"to": "not-an-address"}, "to is not an email address"),
        ({"app_password": ""}, "app_password is missing"),
        ({"app_password": "paste it here, never in chat"}, "app_password is missing"),
        ({"app_password": "short"}, "16-letter"),
        ({"smtp_port": "abc"}, "smtp_port must be a number"),
    ],
)
def test_incomplete_settings_are_reported(tmp_path, change, expected):
    cfg = cfg_with({**GOOD, **change}, tmp_path)
    st, problem = email_mod.email_settings(cfg)
    assert st is None and expected in problem
    assert senders_from_config(cfg) == []
    assert PASSWORD not in problem


def test_to_defaults_to_username(tmp_path):
    st, _ = email_mod.email_settings(
        cfg_with({k: v for k, v in GOOD.items() if k != "to"}, tmp_path)
    )
    assert st.to == GOOD["username"]


# ---------------------------------------------------------------- sending


def test_send_uses_starttls_login_and_both_bodies(tmp_path, fake_smtp):
    [sender] = senders_from_config(cfg_with(GOOD, tmp_path))
    sender.send(message(severity="high"))
    [smtp] = fake_smtp.instances
    assert (smtp.host, smtp.port) == ("smtp.gmail.com", 587)
    assert smtp.calls == ["ehlo", "starttls", "ehlo", "login", "send", "quit"]
    assert smtp.login_args == (GOOD["username"], PASSWORD)
    msg = smtp.sent[0]
    assert msg["Subject"].startswith("[NetWatch]")
    assert msg["To"] == GOOD["to"] and GOOD["username"] in msg["From"]
    assert msg["X-Priority"] == "1"
    types = [p.get_content_type() for p in msg.iter_parts()]
    assert types == ["text/plain", "text/html"]


def test_pc_name_never_in_headers(tmp_path, fake_smtp):
    import socket

    [sender] = senders_from_config(cfg_with(GOOD, tmp_path))
    sender.send(message())
    smtp = fake_smtp.instances[0]
    assert smtp.local_hostname == email_mod.NEUTRAL_HOST
    msg_id = smtp.sent[0]["Message-ID"]
    assert msg_id.endswith(f"@{email_mod.NEUTRAL_HOST}>")
    assert socket.gethostname().lower() not in str(smtp.sent[0]).lower()


def test_bad_login_is_a_clear_send_error_without_the_password(tmp_path, fake_smtp):
    fake_smtp.fail_login = True
    [sender] = senders_from_config(cfg_with(GOOD, tmp_path))
    with pytest.raises(SendError) as exc:
        sender.send(message())
    assert "app password" in str(exc.value) and PASSWORD not in str(exc.value)


def test_network_errors_become_send_errors(tmp_path, fake_smtp):
    fake_smtp.fail_send = OSError("connection reset")
    [sender] = senders_from_config(cfg_with(GOOD, tmp_path))
    with pytest.raises(SendError, match="connection reset"):
        sender.send(message())


def test_send_test_alert(tmp_path, fake_smtp):
    ok, detail = send_test_alert(cfg_with(GOOD, tmp_path))
    assert ok and fake_smtp.instances[0].sent[0]["Subject"] == "[NetWatch] Test alert"
    fake_smtp.fail_login = True
    ok, detail = send_test_alert(cfg_with(GOOD, tmp_path))
    assert not ok and "rejected" in detail
    ok, detail = send_test_alert(cfg_with(None, tmp_path))
    assert not ok and "No alert channel" in detail
    ok, detail = send_test_alert(cfg_with({**GOOD, "to": "x"}, tmp_path))
    assert not ok and "need fixing" in detail
