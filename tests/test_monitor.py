"""The monitor loop's steps, driven by a fake probe on the sample network."""

import asyncio
import json

from sqlalchemy import select

from netwatch.config import Config, Paths
from netwatch.db import make_sessionmaker
from netwatch.models import Alert, Device, PortScan
from netwatch.monitor import Monitor
from netwatch.ports import PortResult
from tests.test_discovery_parsing import FakeProbe, adapter_rows


def make_monitor(engine, tmp_path, probe):
    cfg = Config(paths=Paths(tmp_path), raw={"scan": {"resolve_names": False}})
    mon = Monitor(cfg, make_sessionmaker(engine), probe=probe, allow_sample=True)
    return mon


def test_scan_then_port_check(engine, tmp_path, monkeypatch):
    probe = FakeProbe()
    mon = make_monitor(engine, tmp_path, probe)
    monkeypatch.setattr("netwatch.discovery.scan.asyncio.sleep", _no_sleep)
    report = asyncio.run(mon.scan_once())
    assert report.baseline and report.port_scans_queued == 4

    checked = []

    def fake_check(ip, subnets, **kw):
        checked.append(ip)
        return PortResult("nmap", [{"port": 23, "service": "telnet"}])

    monkeypatch.setattr("netwatch.monitor.check_device", fake_check)
    while asyncio.run(mon.port_check_next()):
        pass
    assert len(checked) == 4
    s = make_sessionmaker(engine)()
    assert all(p.status == "done" for p in s.scalars(select(PortScan)))
    # One of the four is this PC, which checks itself and never raises port alerts.
    assert len(list(s.scalars(select(Alert).where(Alert.kind == "risky_port")))) == 3

    # A new device on the next scan alerts once.
    probe.neighbor_rows.append(
        type(probe.neighbor_rows[0])("192.0.2.70", "02:00:00:00:07:01", "reachable")
    )
    report2 = asyncio.run(mon.scan_once())
    assert len(report2.new_device_ids) == 1 and len(report2.alert_ids) == 1
    s.close()


def test_port_check_waits_for_a_subnet(engine, tmp_path):
    mon = make_monitor(engine, tmp_path, FakeProbe())
    assert asyncio.run(mon.port_check_next()) is False


def test_no_adapter_is_recorded_as_failed_scan(engine, tmp_path, monkeypatch):
    rows = [r for r in adapter_rows() if r["alias"] != "Ethernet"]
    mon = make_monitor(engine, tmp_path, FakeProbe(rows=rows))
    report = asyncio.run(mon.scan_once())
    assert not report.health.ok
    s = make_sessionmaker(engine)()
    assert s.scalar(select(Device)) is None
    s.close()
    assert json.dumps(report.health.reason)


async def _no_sleep(_seconds):
    return None


def test_sample_data_refuses_the_real_data_folder(monkeypatch):
    from netwatch.__main__ import main
    from netwatch.config import DEFAULT_DATA_DIR

    monkeypatch.setenv("NETWATCH_DATA_DIR", DEFAULT_DATA_DIR)
    assert main(["sample-data"]) == 1


def test_monitor_backs_up_when_due_and_records_failures(engine, tmp_path):
    from datetime import datetime
    from pathlib import Path

    from netwatch import backup
    from netwatch.services.common import set_setting

    folder = tmp_path / "backups"
    cfg = Config(paths=Paths(tmp_path), raw={"backup": {"dir": str(folder)}})
    mon = Monitor(cfg, make_sessionmaker(engine), probe=FakeProbe(), allow_sample=True)
    assert mon.backup_if_due(datetime.now())  # never backed up: right away
    assert len(list(folder.glob("netwatch-*.db"))) == 1
    assert not mon.backup_if_due(datetime.now())  # done today

    # A missing drive is recorded (banner, email), not raised, so the loop keeps going.
    letter = next(c for c in "QRSTUVWXYZ" if not Path(f"{c}:\\").exists())
    cfg.raw["backup"]["dir"] = f"{letter}:\\Backups\\NetWatch"
    with make_sessionmaker(engine)() as s:
        set_setting(s, backup.OK_KEY, "2020-01-01T02:30:00")  # long ago -> due
        s.commit()
    assert mon.backup_if_due(datetime.now())
    with make_sessionmaker(engine)() as s:
        assert "not connected" in backup.status(s, cfg.backup_dir).problem
        assert s.scalar(select(Alert).where(Alert.kind == "backup_failed")) is not None
