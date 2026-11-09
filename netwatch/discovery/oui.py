"""Vendor lookup from the MAC prefix (OUI).

Uses an offline copy of the public Wireshark ``manuf`` list, downloaded at
runtime into the data folder (never committed) and refreshed monthly.
Supports the /24 (3-byte) entries and the longer /28 and /36 blocks.
"""

from __future__ import annotations

import logging
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from netwatch.netutil import mac_digits

log = logging.getLogger("netwatch.oui")
MAX_DOWNLOAD = 20_000_000


@dataclass
class VendorDB:
    # prefix bit length -> {hex prefix (bits // 4 chars) -> vendor}
    tables: dict[int, dict[str, str]] = field(default_factory=dict)

    def __len__(self) -> int:
        return sum(len(t) for t in self.tables.values())

    def lookup(self, mac: str | None) -> str:
        if not mac:
            return ""
        digits = mac_digits(mac)
        for bits in sorted(self.tables, reverse=True):  # longest prefix wins
            vendor = self.tables[bits].get(digits[: bits // 4])
            if vendor:
                return vendor
        return ""


def parse_manuf(text: str) -> VendorDB:
    db = VendorDB()
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        parts = [p.strip() for p in line.split("\t") if p.strip()]
        if len(parts) < 2:
            parts = line.split(None, 2)
            if len(parts) < 2:
                continue
        prefix, short = parts[0], parts[1]
        long_name = parts[2] if len(parts) > 2 else short
        bits = 24
        if "/" in prefix:
            prefix, bits_s = prefix.split("/", 1)
            try:
                bits = int(bits_s)
            except ValueError:
                continue
        digits = "".join(ch for ch in prefix.lower() if ch in "0123456789abcdef")
        if bits % 4 or len(digits) * 4 < bits:
            continue
        db.tables.setdefault(bits, {})[digits[: bits // 4]] = long_name
    return db


def cache_is_stale(path: Path, refresh_days: int, now: float | None = None) -> bool:
    if not path.exists():
        return True
    age = (now or time.time()) - path.stat().st_mtime
    return age > refresh_days * 86400


def download_manuf(url: str, dest: Path, timeout: int = 60) -> int:
    """Download the vendor list to ``dest`` (atomically). Returns the number of entries."""
    if not url.startswith("https://"):
        raise ValueError("The vendor list URL must use https.")
    req = urllib.request.Request(url, headers={"User-Agent": "home-network-watcher"})  # noqa: S310
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - https only, checked above
        data = resp.read(MAX_DOWNLOAD + 1)
    if len(data) > MAX_DOWNLOAD:
        raise ValueError("Vendor list is unexpectedly large; not saved.")
    text = data.decode("utf-8", errors="replace")
    db = parse_manuf(text)
    if len(db) < 1000:
        raise ValueError("Vendor list looks wrong (too few entries); not saved.")
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(dest)
    return len(db)


def load_vendor_db(path: Path) -> VendorDB:
    if not path.exists():
        return VendorDB()
    return parse_manuf(path.read_text(encoding="utf-8", errors="replace"))


def ensure_vendor_db(path: Path, url: str, refresh_days: int) -> tuple[VendorDB, str | None]:
    """Load the cached list, refreshing it first if it's missing or old.

    Returns (db, problem). A failed refresh keeps the old copy and reports why.
    """
    problem = None
    if cache_is_stale(path, refresh_days):
        try:
            count = download_manuf(url, path)
            log.info("Vendor list refreshed (%d entries)", count)
        except Exception as exc:  # network errors, bad data: keep going with the old copy
            problem = f"Vendor list refresh failed: {exc}"
            log.warning(problem)
    return load_vendor_db(path), problem
