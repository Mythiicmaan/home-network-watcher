"""Draw the README's app screens as SVG, from the FAKE sample network.

    python scripts/make_readme_screens.py

The repo's privacy guardrails block image files, so these are SVG: plain text that the
private-data check can read word by word. Every device, address, and alert comes from the
sample network (192.0.2.0/24, MACs 02:00:00:xx:xx:xx), built fresh in a temporary folder.
"""

from __future__ import annotations

import sys
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sqlalchemy import select  # noqa: E402

from netwatch.db import make_engine, make_sessionmaker, migrate  # noqa: E402
from netwatch.models import Alert, Device, PortScan  # noqa: E402
from netwatch.netutil import mask_mac  # noqa: E402
from netwatch.sample_data import build_sample_db  # noqa: E402
from netwatch.services import devices as devsvc  # noqa: E402
from netwatch.services import reports  # noqa: E402
from netwatch.services.portcheck import latest_result  # noqa: E402

NOW = datetime(2027, 1, 12, 23, 0)  # UTC; the screens show a fixed UTC-5 "local" time
LOCAL = timedelta(hours=-5)
OUT = ROOT / "docs" / "screens"

W, H = 375, 700
PAD = 16
BG, CARD, TEXT, MUTED, LINE = "#f4f6f8", "#ffffff", "#0f172a", "#64748b", "#e2e8f0"
ACCENT, GOOD, BAD, WARN, CHIP = "#2563eb", "#15803d", "#b91c1c", "#b45309", "#eef2f7"
GOOD_BG, BAD_BG, WARN_BG = "#dcfce7", "#fee2e2", "#fef3c7"
FONT = "-apple-system, BlinkMacSystemFont, Segoe UI, Roboto, Helvetica, Arial, sans-serif"
KIND_LABELS = {
    "new_device": "New device",
    "gateway_mac_change": "Gateway MAC changed",
    "ip_conflict": "IP conflict",
    "risky_port": "Risky port",
    "digest": "Weekly digest",
    "backup_failed": "Backup failed",
}


def ago(t: datetime) -> str:
    mins = int((NOW - t).total_seconds() // 60)
    if mins < 60:
        return f"{max(mins, 1)} min ago"
    if mins < 60 * 24:
        return f"{mins // 60} h ago"
    return f"{mins // (60 * 24)} days ago"


def local(t: datetime) -> str:
    lt = t + LOCAL
    return lt.strftime("%a %I:%M %p").replace(" 0", " ")


class Screen:
    def __init__(self, title: str, nav: str):
        self.parts: list[str] = []
        self.rect(0, 0, W, H, fill=BG)
        self.text(PAD, 30, title, 18, weight=700)
        self.line(0, 46, W, 46)
        self.nav = nav

    def rect(self, x, y, w, h, *, r=0, fill=CARD, stroke=None):
        s = f' stroke="{stroke}"' if stroke else ""
        self.parts.append(
            f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{r}" fill="{fill}"{s}/>'
        )

    def line(self, x1, y1, x2, y2, stroke=LINE):
        self.parts.append(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{stroke}"/>')

    def circle(self, x, y, r, fill):
        self.parts.append(f'<circle cx="{x}" cy="{y}" r="{r}" fill="{fill}"/>')

    def text(self, x, y, s, size=14, *, weight=400, fill=TEXT, anchor="start"):
        self.parts.append(
            f'<text x="{x}" y="{y}" font-size="{size}" font-weight="{weight}" fill="{fill}" '
            f'text-anchor="{anchor}">{escape(str(s))}</text>'
        )

    def card(self, y, h, x=PAD, w=W - 2 * PAD):
        self.rect(x, y, w, h, r=14, stroke=LINE)

    def badge(self, x, y, label, *, fg=MUTED, bg=CHIP) -> float:
        w = len(label) * 5.6 + 12
        self.rect(x, y - 11, w, 16, r=8, fill=bg)
        self.text(x + 6, y + 1, label, 10, weight=600, fill=fg)
        return x + w + 4

    def status_badge(self, x, y, status) -> float:
        colors = {
            "known": (GOOD, GOOD_BG, "Known"),
            "unknown": (WARN, WARN_BG, "Unknown"),
            "ignored": (MUTED, CHIP, "Ignored"),
        }
        fg, bg, label = colors[status]
        return self.badge(x, y, label, fg=fg, bg=bg)

    def sev_badge(self, x, y, severity) -> float:
        fg, bg, label = {
            "high": (BAD, BAD_BG, "HIGH"),
            "warning": (WARN, WARN_BG, "Warning"),
            "info": (MUTED, CHIP, "Info"),
        }[severity]
        return self.badge(x, y, label, fg=fg, bg=bg)

    def button(self, right, y, label, *, primary=False):
        w = len(label) * 7 + 20
        self.rect(
            right - w,
            y,
            w,
            28,
            r=9,
            fill=ACCENT if primary else CARD,
            stroke=None if primary else LINE,
        )
        self.text(
            right - w / 2,
            y + 18,
            label,
            12,
            weight=600,
            fill="#fff" if primary else TEXT,
            anchor="middle",
        )

    def bottom_nav(self):
        y = H - 56
        self.rect(0, y, W, 56, fill=CARD)
        self.line(0, y, W, y)
        for i, name in enumerate(("Home", "Devices", "Alerts", "Settings")):
            x = W / 8 + i * W / 4
            on = name == self.nav
            self.circle(x, y + 18, 4, ACCENT if on else MUTED)
            self.text(
                x,
                y + 40,
                name,
                11,
                weight=600 if on else 400,
                fill=ACCENT if on else MUTED,
                anchor="middle",
            )

    def svg(self, alt: str) -> str:
        self.bottom_nav()
        body = "\n  ".join(self.parts)
        return (
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
            f'viewBox="0 0 {W} {H}" font-family="{FONT}" role="img" aria-label="{escape(alt)}">\n'
            f"  <title>{escape(alt)}</title>\n  {body}\n</svg>\n"
        )


def clip(s: str, n: int) -> str:
    return s if len(s) <= n else s[: n - 1] + "…"


def wrap(s: str, n: int, lines: int = 2) -> list[str]:
    out, cur = [], ""
    for word in s.split():
        if cur and len(cur) + 1 + len(word) > n:
            out.append(cur)
            cur = word
        else:
            cur = f"{cur} {word}".strip()
    out.append(cur)
    if len(out) > lines:
        out = out[: lines - 1] + [clip(" ".join(out[lines - 1 :]), n)]
    return out


# ---------------------------------------------------------------- screens


def home(s) -> str:
    sc = Screen("Home Network", "Home")
    sm = reports.summary(s, NOW)
    last = reports.last_scan(s)
    y = 60
    sc.card(y, 120)
    sc.text(PAD + 14, y + 22, "SCAN HEALTH", 10, weight=600, fill=MUTED)
    sc.circle(PAD + 19, y + 42, 5, GOOD)
    sc.text(PAD + 30, y + 47, "Healthy", 17, weight=700)
    sc.text(W - PAD - 14, y + 26, f"Last scan {ago(last.started_at)}", 11, fill=MUTED, anchor="end")
    sc.text(W - PAD - 14, y + 42, f"{last.hosts_found} devices found", 11, fill=MUTED, anchor="end")
    for i, (label, value, color) in enumerate(
        (
            ("Online now", sm.online, TEXT),
            ("Unknown", sm.unknown, WARN),
            ("Open alerts", sm.unacknowledged, BAD),
        )
    ):
        x = PAD + 14 + i * 110
        sc.text(x, y + 78, label.upper(), 9, weight=600, fill=MUTED)
        sc.text(x, y + 104, value, 22, weight=700, fill=color if value else TEXT)

    y = 194
    unknown = list(
        s.scalars(
            select(Device).where(Device.status == "unknown").order_by(Device.first_seen.desc())
        )
    )
    sc.card(y, 46 + 82 * len(unknown))
    sc.text(PAD + 14, y + 28, "Needs a look", 15, weight=700)
    sc.text(W - PAD - 14, y + 28, "All unknown →", 12, fill=ACCENT, anchor="end")
    online = reports.online_ids(s)
    for i, d in enumerate(unknown):
        ry = y + 46 + i * 82
        sc.line(PAD, ry, W - PAD, ry)
        sc.circle(PAD + 18, ry + 20, 4, GOOD if d.id in online else MUTED)
        x = PAD + 28
        sc.text(x, ry + 24, d.display_name, 14, weight=700)
        if d.is_randomized_mac:
            sc.badge(x + len(d.display_name) * 8 + 6, ry + 22, "Private address", fg=ACCENT)
        sub = f"{d.vendor or 'Unknown vendor'} · {d.last_ip} · first seen {ago(d.first_seen)}"
        sc.text(x, ry + 42, clip(sub, 52), 11, fill=MUTED)
        sc.button(W - PAD - 82, ry + 48, "Known", primary=True)
        sc.button(W - PAD - 14, ry + 48, "Ignore")

    y += 46 + 82 * len(unknown) + 14
    risky = reports.latest_risky(s)
    shown = risky[:3]
    sc.card(y, 46 + 46 * len(shown))
    sc.text(PAD + 14, y + 28, "Risky ports open", 15, weight=700)
    for i, (d, p) in enumerate(shown):
        ry = y + 46 + i * 46
        sc.line(PAD, ry, W - PAD, ry)
        sc.text(PAD + 14, ry + 20, d.display_name, 13, weight=700)
        ports = " · ".join(f"{r['port']} {r['service']}" for r in p.risky_ports)
        sc.text(PAD + 14, ry + 37, clip(ports, 50), 11, fill=MUTED)
        high = any(r["severity"] == "high" for r in p.risky_ports)
        sc.badge(
            W - PAD - 30,
            ry + 26,
            str(len(p.risky_ports)),
            fg=BAD if high else WARN,
            bg=BAD_BG if high else WARN_BG,
        )

    y += 46 + 46 * len(shown) + 14
    sc.text(
        W / 2,
        min(y + 10, H - 70),
        f"{sm.devices} devices in the inventory · {sm.new_this_week} new this week",
        11,
        fill=MUTED,
        anchor="middle",
    )
    return sc.svg("Dashboard: scan health, devices that need a look, risky ports open")


def devices(s) -> str:
    sc = Screen("Devices", "Devices")
    online = reports.online_ids(s)
    rows = devsvc.list_devices(s, online, sort="online")
    sc.rect(PAD, 58, W - 2 * PAD, 36, r=10, stroke=LINE)
    sc.text(PAD + 12, 81, "Search name, vendor, IP, MAC…", 13, fill=MUTED)
    y = 106
    shown = rows[:8]
    sc.card(y, 58 * len(shown))
    for i, row in enumerate(shown):
        d = row.device
        ry = y + i * 58
        if i:
            sc.line(PAD, ry, W - PAD, ry)
        sc.circle(PAD + 18, ry + 21, 4, GOOD if row.online else MUTED)
        name = d.display_name + (f" · {d.owner}" if d.owner else "")
        sc.text(PAD + 30, ry + 25, clip(name, 30), 14, weight=700)
        sc.text(W - PAD - 12, ry + 25, d.last_ip, 12, fill=MUTED, anchor="end")
        x = sc.status_badge(PAD + 30, ry + 44, d.status)
        if d.is_randomized_mac:
            x = sc.badge(x, ry + 44, "Private address", fg=ACCENT)
        if d.is_gateway:
            x = sc.badge(x, ry + 44, "Gateway")
        if d.is_this_pc:
            x = sc.badge(x, ry + 44, "This PC")
        sc.text(W - PAD - 12, ry + 46, mask_mac(d.mac), 10, fill=MUTED, anchor="end")
    sc.text(
        W / 2,
        y + 58 * len(shown) + 22,
        f"{len(rows)} devices · tap a MAC to reveal it",
        11,
        fill=MUTED,
        anchor="middle",
    )
    return sc.svg("Device list with status, private-address and gateway badges, masked MACs")


def device_page(s) -> str:
    d = s.scalar(select(Device).where(Device.vendor == "Example IoT Modules"))
    sc = Screen(d.display_name, "Devices")
    y = 58
    sc.card(y, 142)
    sc.status_badge(PAD + 14, y + 24, d.status)
    online = d.id in reports.online_ids(s)
    sc.text(
        W - PAD - 14,
        y + 26,
        "Online now" if online else f"Last seen {ago(d.last_seen)}",
        12,
        fill=MUTED,
        anchor="end",
    )
    facts = (
        ("Vendor", d.vendor),
        ("Hostname", d.hostname or "—"),
        ("IP address", d.last_ip),
        ("MAC address", mask_mac(d.mac)),
        ("First seen", ago(d.first_seen)),
    )
    for i, (k, v) in enumerate(facts):
        sc.text(PAD + 14, y + 50 + i * 20, k, 12, fill=MUTED)
        sc.text(PAD + 110, y + 50 + i * 20, v, 13)

    y = 212
    sc.card(y, 170)
    sc.text(PAD + 14, y + 26, "Online, last 7 days", 15, weight=700)
    timeline = reports.presence_timeline(s, d.id, NOW, days=7)
    cell, gap = 10, 1.5
    left = PAD + 52
    rows: dict[str, int] = {}
    for t, seen in timeline:
        lt = t + LOCAL
        row = rows.setdefault(lt.strftime("%a %d"), len(rows))
        if row >= 8:
            continue
        ry = y + 40 + row * (cell + 3)
        if lt.hour == 0 or row == 0 and lt == timeline[0][0] + LOCAL:
            sc.text(PAD + 14, ry + 9, lt.strftime("%a"), 10, fill=MUTED)
        sc.rect(left + lt.hour * (cell + gap), ry, cell, cell, r=2, fill=GOOD if seen else LINE)
    for h, label in ((0, "12a"), (6, "6a"), (12, "12p"), (18, "6p")):
        sc.text(left + h * (cell + gap), y + 160, label, 9, fill=MUTED)

    y = 394
    scan = latest_result(s, d.id)
    findings = scan.risky_ports if scan else []
    sc.card(y, 64 + 86 * len(findings))
    sc.text(PAD + 14, y + 26, "Port check", 15, weight=700)
    sc.button(W - PAD - 14, y + 10, "Scan now")
    sc.text(PAD + 14, y + 48, "Nmap TCP connect scan · top 100 ports", 11, fill=MUTED)
    for i, f in enumerate(findings):
        ry = y + 56 + i * 86
        high = f["severity"] == "high"
        sc.rect(PAD + 10, ry, W - 2 * PAD - 20, 80, r=10, fill=BAD_BG if high else WARN_BG)
        sc.text(PAD + 20, ry + 20, f"{f['port']}/tcp · {f['service']}", 13, weight=700)
        for j, line in enumerate(wrap(f["why"], 54)):
            sc.text(PAD + 20, ry + 38 + j * 14, line, 11)
        sc.text(PAD + 20, ry + 70, clip("What to do: " + f["fix"], 56), 11, fill=MUTED)
    return sc.svg("Device page: facts, a 7-day online timeline, and port check findings")


def alerts(s) -> str:
    sc = Screen("Alerts", "Alerts")
    items = list(s.scalars(select(Alert).order_by(Alert.created_at.desc(), Alert.id.desc())))[:6]
    y = 58
    for label, on in (("Open", True), ("All", False)):
        w = 56
        sc.rect(PAD if on else PAD + w + 6, y, w, 28, r=14, fill=ACCENT if on else CHIP)
        sc.text(
            (PAD if on else PAD + w + 6) + w / 2,
            y + 18,
            label,
            12,
            weight=600,
            fill="#fff" if on else TEXT,
            anchor="middle",
        )
    y = 98
    for a in items:
        h = 88
        sc.card(y, h)
        x = sc.sev_badge(PAD + 14, y + 22, a.severity)
        sc.text(x + 2, y + 23, clip(a.title, 40), 12, weight=700)
        sc.text(
            PAD + 14,
            y + 44,
            f"{KIND_LABELS.get(a.kind, a.kind)} · {local(a.created_at)}"
            f" · {'sent' if a.sent_ok else 'waiting'}",
            11,
            fill=MUTED,
        )
        first = a.message.split("\n")[0]
        sc.text(PAD + 14, y + 66, clip(first, 56 if a.acknowledged else 32), 11)
        if not a.acknowledged:
            sc.button(W - PAD - 14, y + 48, "Acknowledge")
        y += h + 10
        if y > H - 150:
            break
    return sc.svg("Alerts: new devices and risky ports, each sent once, with Acknowledge")


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        engine = make_engine(Path(tmp) / "netwatch.db")
        migrate(engine)
        s = make_sessionmaker(engine)()
        build_sample_db(s, NOW)
        s.commit()
        # The sample builder adds port checks; make sure the printer's result is "done".
        assert s.scalar(select(PortScan).where(PortScan.status == "done")) is not None
        for name, fn in (
            ("home", home),
            ("devices", devices),
            ("device", device_page),
            ("alerts", alerts),
        ):
            (OUT / f"{name}.svg").write_text(fn(s), encoding="utf-8")
            print(f"wrote docs/screens/{name}.svg")
        s.close()
        engine.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
