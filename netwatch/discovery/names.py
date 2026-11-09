"""Hostnames: reverse DNS, NetBIOS node status, and unicast mDNS.

Each is one ordinary, standard query to a device on the home subnet. Nothing
is spoofed and nothing needs admin rights.
"""

from __future__ import annotations

import ipaddress
import secrets
import socket
import struct

NBSTAT_PORT = 137
MDNS_PORT = 5353


# ---------------------------------------------------------------- reverse DNS


def reverse_dns(ip: str, timeout: float = 2.0) -> str:
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        name = socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        return ""
    finally:
        socket.setdefaulttimeout(old)
    return clean_hostname(name, ip)


def clean_hostname(name: str, ip: str = "") -> str:
    name = (name or "").strip().rstrip(".")
    if not name or name == ip:
        return ""
    # A name that's just the address spelled out (ISP-style PTR) says nothing useful.
    if ip and ip.replace(".", "-") in name:
        return ""
    return name


# ---------------------------------------------------------------- NetBIOS


def _nb_encode(name: str) -> bytes:
    raw = name.ljust(16, "\x00")[:16].encode("ascii")
    out = bytearray([32])
    for b in raw:
        out += bytes([0x41 + (b >> 4), 0x41 + (b & 0x0F)])
    return bytes(out + b"\x00")


def build_nbstat_query(txid: int) -> bytes:
    header = struct.pack(">HHHHHH", txid, 0x0000, 1, 0, 0, 0)
    return header + _nb_encode("*") + struct.pack(">HH", 0x0021, 0x0001)


def parse_nbstat_response(data: bytes, txid: int | None = None) -> str:
    """Return the device's unique workstation name (suffix 0x00), or ''."""
    try:
        rid, _flags, _qd, an, _ns, _ar = struct.unpack(">HHHHHH", data[:12])
        if (txid is not None and rid != txid) or an < 1:
            return ""
        pos = 12
        # Name field: length-prefixed labels ending in 0 (may be a pointer in theory).
        if data[pos] & 0xC0 == 0xC0:
            pos += 2
        else:
            while data[pos] != 0:
                pos += 1 + data[pos]
            pos += 1
        rtype, _rclass, _ttl, _rdlen = struct.unpack(">HHIH", data[pos : pos + 10])
        if rtype != 0x0021:
            return ""
        pos += 10
        count = data[pos]
        pos += 1
        for _ in range(count):
            entry = data[pos : pos + 18]
            if len(entry) < 18:
                break
            name = entry[:15].decode("ascii", errors="replace").rstrip(" \x00")
            suffix = entry[15]
            flags = struct.unpack(">H", entry[16:18])[0]
            pos += 18
            if suffix == 0x00 and not flags & 0x8000 and name:
                return name
    except (IndexError, struct.error):
        return ""
    return ""


def netbios_name(ip: str, timeout: float = 1.0) -> str:
    ipaddress.IPv4Address(ip)
    txid = secrets.randbelow(0xFFFF)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.sendto(build_nbstat_query(txid), (ip, NBSTAT_PORT))
            data, _ = sock.recvfrom(2048)
        except OSError:
            return ""
    return parse_nbstat_response(data, txid)


# ---------------------------------------------------------------- DNS / mDNS


def reverse_name(ip: str) -> str:
    return ".".join(reversed(ip.split("."))) + ".in-addr.arpa"


def _encode_qname(name: str) -> bytes:
    out = bytearray()
    for label in name.strip(".").split("."):
        b = label.encode("ascii")
        out += bytes([len(b)]) + b
    return bytes(out + b"\x00")


def build_ptr_query(txid: int, ip: str) -> bytes:
    header = struct.pack(">HHHHHH", txid, 0x0000, 1, 0, 0, 0)
    return header + _encode_qname(reverse_name(ip)) + struct.pack(">HH", 12, 1)


def _read_name(data: bytes, pos: int, depth: int = 0) -> tuple[str, int]:
    labels = []
    jumped_end = None
    while True:
        if depth > 20:
            raise ValueError("compression loop")
        length = data[pos]
        if length == 0:
            pos += 1
            break
        if length & 0xC0 == 0xC0:
            ptr = ((length & 0x3F) << 8) | data[pos + 1]
            if jumped_end is None:
                jumped_end = pos + 2
            pos = ptr
            depth += 1
            continue
        labels.append(data[pos + 1 : pos + 1 + length].decode("utf-8", errors="replace"))
        pos += 1 + length
    return ".".join(labels), (jumped_end if jumped_end is not None else pos)


def parse_ptr_response(data: bytes, txid: int | None = None) -> str:
    """First PTR answer's target name (without a trailing dot), or ''."""
    try:
        rid, flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", data[:12])
        if (txid is not None and rid != txid) or not flags & 0x8000 or an < 1:
            return ""
        pos = 12
        for _ in range(qd):
            _, pos = _read_name(data, pos)
            pos += 4
        for _ in range(an):
            _, pos = _read_name(data, pos)
            rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", data[pos : pos + 10])
            pos += 10
            if rtype == 12:
                name, _ = _read_name(data, pos)
                return name.rstrip(".")
            pos += rdlen
    except (IndexError, struct.error, ValueError):
        return ""
    return ""


def mdns_name(ip: str, timeout: float = 1.0) -> str:
    """Ask the device itself (unicast to port 5353) for its .local name. Apple devices,
    printers, and many smart-home devices answer."""
    ipaddress.IPv4Address(ip)
    txid = secrets.randbelow(0xFFFF)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.sendto(build_ptr_query(txid, ip), (ip, MDNS_PORT))
            data, _ = sock.recvfrom(4096)
        except OSError:
            return ""
    name = parse_ptr_response(data, txid)
    return name


def best_hostname(ip: str) -> tuple[str, str]:
    """Try mDNS, NetBIOS, then reverse DNS. Returns (name, source)."""
    for source, fn in (("mdns", mdns_name), ("netbios", netbios_name), ("dns", reverse_dns)):
        try:
            name = clean_hostname(fn(ip), ip)
        except (OSError, ValueError):
            name = ""
        if name:
            return name, source
    return "", ""
