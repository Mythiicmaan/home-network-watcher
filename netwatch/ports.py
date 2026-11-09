"""Port checks for devices: Nmap TCP connect scan, with a built-in fallback.

- Nmap ``-sT`` (TCP connect) needs no admin rights and sends only normal
  connection attempts. No SYN/stealth scans, no scripts, no OS detection.
- If Nmap is missing or won't run under the service account, a small asyncio
  connect check of a curated port list is used instead.
- Every target is checked against the home subnet first (netutil).
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import os
import shutil
import subprocess  # noqa: S404 - runs nmap with a validated IP and fixed flags
import xml.etree.ElementTree as ET  # noqa: S405 - parses our own local nmap's output
from dataclasses import dataclass, field

from netwatch.netutil import ensure_target_allowed


@dataclass(frozen=True)
class RiskyPort:
    port: int
    service: str
    severity: str  # warning | high
    why: str
    fix: str


RISKY_PORTS: dict[int, RiskyPort] = {
    p.port: p
    for p in [
        RiskyPort(
            23,
            "Telnet",
            "high",
            "Telnet sends everything, including passwords, as plain text, and is a favorite target of botnets like Mirai.",
            "Turn Telnet off in the device's settings or update its firmware. Use SSH if you need remote access.",
        ),
        RiskyPort(
            21,
            "FTP",
            "warning",
            "FTP sends logins and files unencrypted, and often allows anonymous access.",
            "Turn FTP off, or switch to SFTP.",
        ),
        RiskyPort(
            445,
            "SMB (file sharing)",
            "warning",
            "Windows file sharing. Expected on a PC that shares folders, but it's how worms like WannaCry spread.",
            "If you don't share files from this device, turn off file sharing. Keep Windows updated.",
        ),
        RiskyPort(
            139,
            "NetBIOS session (old file sharing)",
            "warning",
            "Legacy Windows file sharing (SMBv1 era).",
            "Turn off NetBIOS over TCP/IP and SMBv1 unless an old device needs it.",
        ),
        RiskyPort(
            3389,
            "Remote Desktop (RDP)",
            "high",
            "Lets someone control this computer remotely. Heavily attacked when exposed.",
            "Turn off Remote Desktop if you don't use it. Never forward it through the router.",
        ),
        RiskyPort(
            5900,
            "VNC remote control",
            "high",
            "Screen-sharing / remote control, often with weak or no password.",
            "Turn VNC off or require a strong password; never forward it through the router.",
        ),
        RiskyPort(
            1900,
            "UPnP (SSDP)",
            "warning",
            "UPnP lets devices open holes in the router's firewall automatically.",
            "Consider turning UPnP off on the gateway and on this device.",
        ),
        RiskyPort(
            5000,
            "UPnP / device web service",
            "warning",
            "Often a UPnP control service or an unencrypted admin page.",
            "Check what's listening; turn off UPnP if you don't need it.",
        ),
        RiskyPort(
            80,
            "Unencrypted web page (HTTP)",
            "warning",
            "An admin or setup page without encryption: anyone on the network can read the login.",
            "Use the HTTPS page if the device has one, and change any default password.",
        ),
        RiskyPort(
            8080,
            "Unencrypted web page (HTTP alt)",
            "warning",
            "A second unencrypted web/admin page.",
            "Use HTTPS if available and change any default password.",
        ),
    ]
}

# Used by the fallback (and always merged into Nmap's list): common services + every risky port.
BUILTIN_PORTS = sorted(
    set(RISKY_PORTS)
    | {22, 53, 110, 135, 143, 443, 515, 548, 554, 631, 993, 995, 1883, 3306, 5353, 5357, 7000}
    | {8000, 8008, 8009, 8443, 8888, 9100, 32400, 49152, 62078}
)


@dataclass
class PortResult:
    method: str
    open_ports: list[dict] = field(default_factory=list)  # [{"port": 80, "service": "http"}]
    error: str = ""
    note: str = ""  # e.g. why the built-in check was used instead of Nmap

    @property
    def ports(self) -> list[int]:
        return sorted(p["port"] for p in self.open_ports)


def risky_findings(open_ports: list[int]) -> list[dict]:
    out = []
    for port in sorted(open_ports):
        r = RISKY_PORTS.get(port)
        if r:
            out.append(
                {
                    "port": port,
                    "service": r.service,
                    "severity": r.severity,
                    "why": r.why,
                    "fix": r.fix,
                }
            )
    return out


# ---------------------------------------------------------------- nmap


def find_nmap(configured: str) -> str | None:
    if configured and os.path.isfile(configured):
        return configured
    return shutil.which("nmap")


def nmap_command(nmap: str, ip: str, top_ports: int) -> list[str]:
    ipaddress.IPv4Address(ip)
    return [
        nmap,
        "-sT",  # TCP connect scan: no admin, no raw packets
        "-Pn",  # we already know it's up
        "-n",  # no DNS
        "--top-ports",
        str(int(top_ports)),
        "-T3",
        "--max-retries",
        "1",
        "--host-timeout",
        "120s",
        "-oX",
        "-",
        ip,
    ]


def parse_nmap_xml(text: str) -> list[dict]:
    root = ET.fromstring(text)  # noqa: S314 - trusted output of our own nmap process
    out = []
    for port in root.iter("port"):
        state = port.find("state")
        if state is None or state.get("state") != "open" or port.get("protocol") != "tcp":
            continue
        svc = port.find("service")
        out.append(
            {
                "port": int(port.get("portid", "0")),
                "service": (svc.get("name", "") if svc is not None else ""),
            }
        )
    return sorted(out, key=lambda p: p["port"])


def run_nmap(nmap: str, ip: str, top_ports: int, timeout: int = 180) -> PortResult:
    cmd = nmap_command(nmap, ip, top_ports)
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout, check=False)  # noqa: S603
    except (OSError, subprocess.TimeoutExpired) as exc:
        return PortResult("nmap", error=f"Nmap didn't run: {exc}")
    out = r.stdout.decode("utf-8", errors="replace")
    if r.returncode != 0 or "<nmaprun" not in out:
        err = r.stderr.decode("utf-8", errors="replace").strip().splitlines()
        return PortResult("nmap", error=f"Nmap failed: {err[-1] if err else r.returncode}")
    try:
        found = parse_nmap_xml(out)
    except ET.ParseError as exc:
        return PortResult("nmap", error=f"Couldn't read Nmap output: {exc}")
    # Nmap's top-100 list doesn't include every risky port; check the rest ourselves.
    missing = [p for p in RISKY_PORTS if p not in {f["port"] for f in found}]
    extra = asyncio.run(connect_scan(ip, missing)) if missing else []
    known = {f["port"] for f in found}
    found += [{"port": p, "service": ""} for p in extra if p not in known]
    return PortResult("nmap", sorted(found, key=lambda p: p["port"]))


# ---------------------------------------------------------------- built-in fallback


async def _probe(ip: str, port: int, timeout: float) -> bool:
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
    except (OSError, TimeoutError):
        return False
    writer.close()
    with contextlib.suppress(OSError):
        await writer.wait_closed()
    return True


async def connect_scan(ip: str, ports: list[int], timeout: float = 1.5, concurrency: int = 20):
    ipaddress.IPv4Address(ip)
    sem = asyncio.Semaphore(concurrency)

    async def one(p: int) -> int | None:
        async with sem:
            return p if await _probe(ip, p, timeout) else None

    results = await asyncio.gather(*(one(p) for p in ports))
    return sorted(p for p in results if p is not None)


def check_device(ip: str, subnets, *, nmap_path: str, top_ports: int, allow_sample=False):
    """Port-check one device. Refuses anything outside the home subnet."""
    ensure_target_allowed(ip, subnets, allow_sample=allow_sample)
    nmap = find_nmap(nmap_path)
    if nmap:
        result = run_nmap(nmap, ip, top_ports)
        if not result.error:
            return result
        note = result.error
    else:
        note = "Nmap not found"
    ports = asyncio.run(connect_scan(ip, BUILTIN_PORTS))
    return PortResult("builtin", [{"port": p, "service": ""} for p in ports], note=note)
