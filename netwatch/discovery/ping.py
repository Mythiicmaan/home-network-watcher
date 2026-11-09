"""Parallel ICMP echo sweep, no admin rights needed.

On Windows this calls the built-in ICMP helper API (``IcmpSendEcho`` in
iphlpapi.dll), the same thing ``ping.exe`` uses, so there is no output to
parse and no localization trouble. Elsewhere it falls back to ``ping``.
"""

from __future__ import annotations

import asyncio
import ctypes
import ipaddress
import subprocess  # noqa: S404 - only runs the system ping with a validated IP
import sys
from collections.abc import Awaitable, Callable

PingFunc = Callable[[str, int], bool]


class _IcmpEchoReply(ctypes.Structure):
    _fields_ = [
        ("Address", ctypes.c_ulong),
        ("Status", ctypes.c_ulong),
        ("RoundTripTime", ctypes.c_ulong),
        ("DataSize", ctypes.c_ushort),
        ("Reserved", ctypes.c_ushort),
        ("Data", ctypes.c_void_p),
        ("Ttl", ctypes.c_ubyte),
        ("Tos", ctypes.c_ubyte),
        ("Flags", ctypes.c_ubyte),
        ("OptionsSize", ctypes.c_ubyte),
        ("OptionsData", ctypes.c_void_p),
    ]


def _windows_ping(ip: str, timeout_ms: int) -> bool:
    iphlpapi = ctypes.windll.iphlpapi  # type: ignore[attr-defined]
    iphlpapi.IcmpCreateFile.restype = ctypes.c_void_p
    iphlpapi.IcmpSendEcho.argtypes = [
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.c_void_p,
        ctypes.c_ushort,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.c_ulong,
    ]
    iphlpapi.IcmpCloseHandle.argtypes = [ctypes.c_void_p]
    handle = iphlpapi.IcmpCreateFile()
    if not handle or handle == ctypes.c_void_p(-1).value:
        return False
    try:
        dest = int.from_bytes(ipaddress.IPv4Address(ip).packed, "little")
        payload = b"netwatch"
        reply_size = ctypes.sizeof(_IcmpEchoReply) + len(payload) + 8 + 64
        buf = ctypes.create_string_buffer(reply_size)
        n = iphlpapi.IcmpSendEcho(
            handle, dest, payload, len(payload), None, buf, reply_size, timeout_ms
        )
        if n == 0:
            return False
        reply = _IcmpEchoReply.from_buffer_copy(buf)
        return reply.Status == 0 and reply.Address == dest  # IP_SUCCESS from the target itself
    finally:
        iphlpapi.IcmpCloseHandle(handle)


def _subprocess_ping(ip: str, timeout_ms: int) -> bool:
    ipaddress.IPv4Address(ip)  # validated: never pass anything else to a command line
    if sys.platform == "win32":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout_ms / 1000 + 3, check=False)  # noqa: S603
    except (OSError, subprocess.TimeoutExpired):
        return False
    return r.returncode == 0


def default_ping() -> PingFunc:
    return _windows_ping if sys.platform == "win32" else _subprocess_ping


async def sweep(
    hosts: list[str],
    *,
    concurrency: int = 64,
    timeout_ms: int = 700,
    ping: PingFunc | None = None,
) -> set[str]:
    """Ping every host, ``concurrency`` at a time. Returns the IPs that replied."""
    ping = ping or default_ping()
    sem = asyncio.Semaphore(concurrency)
    replied: set[str] = set()

    async def one(ip: str) -> None:
        async with sem:
            ok = await asyncio.to_thread(ping, ip, timeout_ms)
        if ok:
            replied.add(ip)

    await asyncio.gather(*(one(ip) for ip in hosts))
    return replied


AsyncSweep = Callable[[list[str]], Awaitable[set[str]]]
