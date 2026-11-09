"""Port checks: Nmap command and XML parsing, risky-port explanations, target safety."""

import asyncio
import ipaddress

import pytest

from netwatch import ports
from netwatch.netutil import UnsafeTargetError

SUBNET = [ipaddress.IPv4Network("192.0.2.0/24")]

NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sT" version="7.99">
<host><status state="up"/><address addr="192.0.2.50" addrtype="ipv4"/>
<ports>
<extraports state="closed" count="96"/>
<port protocol="tcp" portid="23"><state state="open"/><service name="telnet"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
<port protocol="tcp" portid="443"><state state="filtered"/><service name="https"/></port>
<port protocol="tcp" portid="9100"><state state="open"/><service name="jetdirect"/></port>
</ports></host></nmaprun>
"""


def test_parse_nmap_xml_keeps_open_tcp_only():
    assert ports.parse_nmap_xml(NMAP_XML) == [
        {"port": 23, "service": "telnet"},
        {"port": 80, "service": "http"},
        {"port": 9100, "service": "jetdirect"},
    ]


def test_nmap_command_is_a_connect_scan():
    cmd = ports.nmap_command("nmap", "192.0.2.50", 100)
    assert "-sT" in cmd and "-sS" not in cmd and "-O" not in cmd and "--script" not in cmd
    assert cmd[-1] == "192.0.2.50"
    with pytest.raises(ValueError):
        ports.nmap_command("nmap", "192.0.2.50; calc", 100)


def test_risky_findings_explain_each_port():
    found = ports.risky_findings([22, 23, 80, 443, 3389])
    assert [f["port"] for f in found] == [23, 80, 3389]
    telnet = found[0]
    assert telnet["severity"] == "high" and telnet["why"] and telnet["fix"]


def test_every_listed_risky_port_is_covered():
    for p in (23, 21, 445, 139, 3389, 5900, 1900, 5000, 80, 8080):
        assert p in ports.RISKY_PORTS
        assert p in ports.BUILTIN_PORTS


def test_check_device_refuses_targets_outside_the_subnet():
    for bad in ("192.0.2.0", ".".join(["8"] * 4), "localhost"):
        with pytest.raises(UnsafeTargetError):
            ports.check_device(bad, SUBNET, nmap_path="", top_ports=100, allow_sample=True)


def test_connect_scan_finds_a_listening_port():
    async def go():
        server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        async with server:
            return port, await ports.connect_scan("127.0.0.1", [port, 1], timeout=0.5)

    port, found = asyncio.run(go())
    assert found == [port]


def test_check_device_falls_back_without_nmap(monkeypatch):
    monkeypatch.setattr(ports, "find_nmap", lambda _: None)

    async def fake_scan(ip, plist, **kw):
        return [80]

    monkeypatch.setattr(ports, "connect_scan", fake_scan)
    r = ports.check_device("192.0.2.50", SUBNET, nmap_path="", top_ports=100, allow_sample=True)
    assert r.method == "builtin" and r.ports == [80] and "Nmap not found" in r.note
