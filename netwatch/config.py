"""Locations and local configuration.

Everything comes from the ``NETWATCH_DATA_DIR`` environment variable
(default ``C:\\NetWatchData``). Household settings and secrets live in
``config.toml`` inside that folder, never in source.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from datetime import time
from pathlib import Path
from typing import Any

DEFAULT_DATA_DIR = r"C:\NetWatchData"
DEFAULT_NMAP = r"C:\Program Files (x86)\Nmap\nmap.exe"
WEEKDAYS = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]


@dataclass
class Paths:
    data_dir: Path

    @property
    def db(self) -> Path:
        return self.data_dir / "netwatch.db"

    @property
    def config(self) -> Path:
        return self.data_dir / "config.toml"

    @property
    def logs(self) -> Path:
        return self.data_dir / "logs"

    @property
    def oui_cache(self) -> Path:
        return self.data_dir / "oui" / "manuf.txt"


@dataclass
class Config:
    paths: Paths
    raw: dict[str, Any] = field(default_factory=dict)

    def section(self, *names: str) -> dict[str, Any]:
        value: Any = self.raw
        for name in names:
            value = value.get(name, {}) if isinstance(value, dict) else {}
        return value if isinstance(value, dict) else {}

    # ------------------------------------------------------------ network
    @property
    def subnet_override(self) -> list[str]:
        """Subnets to scan instead of the auto-detected one (empty = auto-detect)."""
        return [str(s) for s in self.section("network").get("subnets", [])]

    @property
    def adapter_override(self) -> str:
        return str(self.section("network").get("adapter", "")).strip()

    # ------------------------------------------------------------ scanning
    @property
    def scan_enabled(self) -> bool:
        return bool(self.section("scan").get("enabled", True))

    @property
    def scan_interval_minutes(self) -> int:
        return max(1, int(self.section("scan").get("interval_minutes", 5)))

    @property
    def ping_concurrency(self) -> int:
        return max(1, int(self.section("scan").get("ping_concurrency", 64)))

    @property
    def ping_timeout_ms(self) -> int:
        return max(100, int(self.section("scan").get("ping_timeout_ms", 700)))

    @property
    def degraded_ratio(self) -> float:
        return float(self.section("scan").get("degraded_ratio", 0.3))

    @property
    def resolve_names(self) -> bool:
        return bool(self.section("scan").get("resolve_names", True))

    # ------------------------------------------------------------ port checks
    @property
    def auto_port_check(self) -> bool:
        return bool(self.section("ports").get("auto_check_new", True))

    @property
    def nmap_path(self) -> str:
        return str(self.section("ports").get("nmap_path", "") or DEFAULT_NMAP)

    @property
    def top_ports(self) -> int:
        return max(1, min(1000, int(self.section("ports").get("top_ports", 100))))

    # ------------------------------------------------------------ alerts
    @property
    def quiet_hours(self) -> tuple[time, time] | None:
        """``"22:00-07:00"`` -> (22:00, 07:00). Empty or missing = off (the default)."""
        raw = str(self.section("alerts").get("quiet_hours", "") or "").strip()
        return parse_quiet_hours(raw)

    @property
    def digest_weekday(self) -> int:
        day = str(self.section("alerts").get("digest_day", "sunday")).strip().lower()
        return WEEKDAYS.index(day) if day in WEEKDAYS else 6

    @property
    def digest_hour(self) -> int:
        return max(0, min(23, int(self.section("alerts").get("digest_hour", 18))))

    @property
    def email(self) -> dict[str, Any]:
        return self.section("alerts", "email")

    # ------------------------------------------------------------ app / auth
    @property
    def extra_allowed_hosts(self) -> list[str]:
        return [str(h).lower() for h in self.section("app").get("extra_allowed_hosts", [])]

    @property
    def public_base_url(self) -> str:
        """Base URL used for links inside alerts (e.g. the Tailscale HTTPS address)."""
        return str(self.section("app").get("base_url", "http://localhost:8766")).rstrip("/")

    @property
    def localhost_skip_pin(self) -> bool:
        return bool(self.section("auth").get("localhost_skip_pin", True))

    @property
    def session_days(self) -> int:
        return int(self.section("auth").get("session_days", 90))

    # ------------------------------------------------------------ backups
    @property
    def backup_dir(self) -> Path | None:
        d = self.section("backup").get("dir")
        return Path(d) if d else None

    # ------------------------------------------------------------ vendor list
    @property
    def oui_url(self) -> str:
        return str(
            self.section("oui").get(
                "url", "https://www.wireshark.org/download/automated/data/manuf"
            )
        )

    @property
    def oui_refresh_days(self) -> int:
        return max(1, int(self.section("oui").get("refresh_days", 30)))


def parse_quiet_hours(raw: str) -> tuple[time, time] | None:
    if not raw:
        return None
    try:
        start_s, end_s = (p.strip() for p in raw.split("-", 1))
        return time.fromisoformat(start_s), time.fromisoformat(end_s)
    except ValueError:
        return None


def get_paths() -> Paths:
    return Paths(Path(os.environ.get("NETWATCH_DATA_DIR", DEFAULT_DATA_DIR)))


def load_config(paths: Paths | None = None) -> Config:
    paths = paths or get_paths()
    raw: dict[str, Any] = {}
    if paths.config.exists():
        with paths.config.open("rb") as fh:
            raw = tomllib.load(fh)
    return Config(paths=paths, raw=raw)
