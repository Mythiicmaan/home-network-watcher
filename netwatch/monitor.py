"""The always-on loop: scan every few minutes, port-check new devices, deliver alerts.

Runs inside the web app process (one scheduled task to manage). Every step is
wrapped so one failure is logged and recorded, and the loop keeps going.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import or_, select
from sqlalchemy.orm import Session, sessionmaker

from netwatch import detect
from netwatch.alerts.dispatch import deliver_pending, senders_from_config
from netwatch.config import Config
from netwatch.db import session_scope
from netwatch.discovery import names as names_mod
from netwatch.discovery.oui import VendorDB, ensure_vendor_db
from netwatch.discovery.scan import DiscoveryResult, Probe, SystemProbe, discover
from netwatch.models import Device, PortScan
from netwatch.ports import PortResult, check_device
from netwatch.services import inventory, portcheck, reports
from netwatch.services.common import OUI_PROBLEM_KEY, set_setting
from netwatch.timeutil import utcnow

log = logging.getLogger("netwatch.monitor")
NAME_REFRESH = timedelta(days=1)


@dataclass
class MonitorState:
    running: bool = False
    scanning: bool = False
    port_checking: str = ""  # IP being checked right now
    last_error: str = ""
    last_result: DiscoveryResult | None = None
    subnets: list[ipaddress.IPv4Network] = field(default_factory=list)
    started_at: datetime | None = None


class Monitor:
    def __init__(
        self,
        cfg: Config,
        factory: sessionmaker[Session],
        *,
        probe: Probe | None = None,
        allow_sample: bool = False,
    ):
        self.cfg = cfg
        self.factory = factory
        self.probe = probe or SystemProbe(cfg.ping_concurrency, cfg.ping_timeout_ms)
        self.allow_sample = allow_sample
        self.vendors = VendorDB()
        self.state = MonitorState()
        self._scan_now = asyncio.Event()
        self._port_work = asyncio.Event()
        self._scan_lock = asyncio.Lock()
        self._tasks: list[asyncio.Task] = []
        self._last_rollup: datetime | None = None

    # ------------------------------------------------------------ lifecycle
    def start(self) -> None:
        self.state.running = True
        self.state.started_at = utcnow()
        self._tasks = [
            asyncio.create_task(self._scan_loop(), name="netwatch-scan"),
            asyncio.create_task(self._port_loop(), name="netwatch-ports"),
            asyncio.create_task(self._alert_loop(), name="netwatch-alerts"),
        ]
        if self.cfg.backup_dir is not None:
            self._tasks.append(asyncio.create_task(self._backup_loop(), name="netwatch-backup"))

    async def stop(self) -> None:
        self.state.running = False
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)

    def request_scan(self) -> None:
        self._scan_now.set()

    def request_port_check(self) -> None:
        self._port_work.set()

    # ------------------------------------------------------------ vendors
    async def load_vendors(self) -> None:
        cfg = self.cfg
        db, problem = await asyncio.to_thread(
            ensure_vendor_db, cfg.paths.oui_cache, cfg.oui_url, cfg.oui_refresh_days
        )
        self.vendors = db
        with session_scope(self.factory) as s:
            set_setting(s, OUI_PROBLEM_KEY, problem or "")

    # ------------------------------------------------------------ scanning
    async def scan_once(self) -> inventory.ApplyReport | None:
        async with self._scan_lock:
            self.state.scanning = True
            try:
                return await self._scan_once()
            finally:
                self.state.scanning = False

    async def _scan_once(self) -> inventory.ApplyReport:
        cfg = self.cfg
        result = await discover(
            self.probe,
            subnet_override=cfg.subnet_override,
            adapter_override=cfg.adapter_override,
            allow_sample=self.allow_sample,
        )
        self.state.last_result = result
        if result.subnets:
            if not self.state.subnets:
                self._port_work.set()  # checks queued before a restart can run now
            self.state.subnets = result.subnets
        with session_scope(self.factory) as s:
            known = inventory.known_macs(s)
        new = [o for o in result.observations if o.mac not in known]
        found_names = await self._resolve([(o.mac, o.ip) for o in new]) if new else {}
        with session_scope(self.factory) as s:
            report = inventory.apply_discovery(
                s,
                result,
                vendors=self.vendors,
                names=found_names,
                degraded_ratio=cfg.degraded_ratio,
                auto_port_check=cfg.auto_port_check,
            )
        if report.port_scans_queued:
            self._port_work.set()
        if report.health.ok and not report.health.degraded:
            await self._refresh_names()
        log.info(
            "Scan: %d devices, %s%s, %d new, %d alerts",
            len(result.observations),
            "degraded" if report.health.degraded else ("ok" if report.health.ok else "failed"),
            f" ({report.health.reason})" if report.health.reason else "",
            len(report.new_device_ids),
            len(report.alert_ids),
        )
        return report

    async def _resolve(self, targets: list[tuple[str, str]]) -> dict[str, tuple[str, str]]:
        if not self.cfg.resolve_names:
            return {}
        sem = asyncio.Semaphore(8)

        async def one(mac: str, ip: str):
            async with sem:
                return mac, await asyncio.to_thread(names_mod.best_hostname, ip)

        pairs = await asyncio.gather(*(one(m, ip) for m, ip in targets))
        return dict(pairs)

    async def _refresh_names(self, limit: int = 8) -> None:
        """Look up names for a few online devices that have none (or a day-old check)."""
        if not self.cfg.resolve_names:
            return
        cutoff = utcnow() - NAME_REFRESH
        with session_scope(self.factory) as s:
            online = reports.online_ids(s)
            rows = s.scalars(
                select(Device)
                .where(
                    Device.id.in_(online),
                    or_(Device.names_checked_at.is_(None), Device.names_checked_at < cutoff),
                )
                .limit(limit)
            )
            targets = [(d.mac, d.last_ip) for d in rows]
        if not targets:
            return
        found = await self._resolve(targets)
        with session_scope(self.factory) as s:
            for mac, (name, source) in found.items():
                d = s.scalar(select(Device).where(Device.mac == mac))
                if d:
                    d.names_checked_at = utcnow()
                    if name:
                        d.hostname, d.hostname_source = name, source

    async def _scan_loop(self) -> None:
        try:
            await self.load_vendors()
        except Exception:
            log.exception("Vendor list load failed")
        while True:
            try:
                await self.scan_once()
                self.state.last_error = ""
                await self._housekeeping()
            except Exception as exc:  # never let the loop die
                log.exception("Scan cycle failed")
                self.state.last_error = str(exc)
            self._scan_now.clear()
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(
                    self._scan_now.wait(), timeout=self.cfg.scan_interval_minutes * 60
                )

    async def _housekeeping(self) -> None:
        now = utcnow()
        with session_scope(self.factory) as s:
            reports.maybe_create_digest(s, now, datetime.now(), self.cfg)
        if self._last_rollup is None or now - self._last_rollup > timedelta(hours=6):
            with session_scope(self.factory) as s:
                reports.rollup_old_sightings(s, now)
            self._last_rollup = now
            if len(self.vendors) == 0:  # first download failed earlier; try again
                await self.load_vendors()

    # ------------------------------------------------------------ port checks
    async def port_check_next(self) -> bool:
        """Run one queued port check. Returns False when the queue is empty."""
        if not self.state.subnets:
            return False
        with session_scope(self.factory) as s:
            job = portcheck.next_queued(s)
            if job is None:
                return False
            job_id = job.id
            ip = portcheck.start(s, job, utcnow())
        self.state.port_checking = ip
        try:
            result = await asyncio.to_thread(
                check_device,
                ip,
                self.state.subnets,
                nmap_path=self.cfg.nmap_path,
                top_ports=self.cfg.top_ports,
                allow_sample=self.allow_sample,
            )
        except Exception as exc:
            log.warning("Port check of %s failed: %s", ip, exc)
            result = PortResult("", error=str(exc))
        finally:
            self.state.port_checking = ""
        with session_scope(self.factory) as s:
            job = s.get(PortScan, job_id)
            portcheck.finish(s, job, result, utcnow())
        return True

    async def _port_loop(self) -> None:
        with session_scope(self.factory) as s:
            portcheck.recover_interrupted(s)
        while True:
            try:
                while await self.port_check_next():
                    await asyncio.sleep(2)  # gentle: one device at a time
            except Exception:
                log.exception("Port check loop error")
            self._port_work.clear()
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._port_work.wait(), timeout=60)

    # ------------------------------------------------------------ alerts
    def deliver_alerts(self) -> None:
        cfg = self.cfg
        senders = senders_from_config(cfg)
        quiet = detect.in_quiet_hours(datetime.now().time(), cfg.quiet_hours)
        with session_scope(self.factory) as s:
            deliver_pending(s, senders, utcnow(), base_url=cfg.public_base_url, quiet=quiet)

    # ------------------------------------------------------------ backups
    def backup_if_due(self, now: datetime | None = None) -> bool:
        """Back up when due (2:30 AM, or catch-up). Failures are recorded, never raised."""
        from netwatch import backup

        cfg = self.cfg
        with session_scope(self.factory) as s:
            if not backup.due(s, now or datetime.now()):
                return False
            # A failure is recorded (banner, /health, one email a day) and retried hourly.
            with contextlib.suppress(backup.BackupError):
                backup.backup_and_record(s, cfg.paths.db, cfg.backup_dir)
        return True

    async def _backup_loop(self) -> None:
        """Checks once a minute whether the nightly backup is due."""
        while True:
            try:
                await asyncio.to_thread(self.backup_if_due)
            except Exception:
                log.exception("Backup loop error")
            await asyncio.sleep(60)

    # ------------------------------------------------------------ alerts
    async def _alert_loop(self) -> None:
        while True:
            try:
                await asyncio.to_thread(self.deliver_alerts)
            except Exception:
                log.exception("Alert delivery loop error")
            await asyncio.sleep(30)
