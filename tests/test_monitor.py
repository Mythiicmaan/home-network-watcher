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
