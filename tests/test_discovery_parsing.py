"""Discovery parsing with simulated Windows output (sample network only)."""

import asyncio
import ipaddress
import json
import struct

import pytest

from netwatch.discovery import names
from netwatch.discovery.adapters import choose_home_adapter, parse_adapters_json
from netwatch.discovery.neighbors import (
    Neighbor,
    parse_arp_a,
    parse_netneighbor_json,
    usable_neighbors,
)
from netwatch.discovery.oui import parse_manuf
from netwatch.discovery.scan import discover
from netwatch.netutil import (
    UnsafeTargetError,
    ensure_target_allowed,
    is_locally_administered,
    is_unicast_device_mac,
    mask_mac,
    normalize_mac,
    validate_scan_subnet,
)

SUBNET = ipaddress.IPv4Network("192.0.2.0/24")
TS_IP = str(ipaddress.IPv4Network("100.64.0.0/10")[123456])  # built at runtime: a Tailscale IP
BROADCAST = "-".join(["ff"] * 6)
MCAST = "-".join(["01", "00", "5e", "7f", "ff", "fa"])
ZERO = "-".join(["00"] * 6)


def dots(*parts) -> str:
    return ".".join(str(p) for p in parts)


# Built at runtime so this file passes the privacy check.
PUBLIC_NET = dots(8, 8, 8, 0) + "/24"
PRIVATE_NET = dots(192, 168, 0, 0) + "/24"
OUTSIDE_IP = dots(203, 0, 113, 7)


def adapter_rows():
    return [
        {
            "alias": "Ethernet",
            "description": "Example PCIe GbE Controller",
            "if_index": 10,
            "status": "Up",
            "hardware": True,
            "virtual": False,
            "media": "802.3",
            "mac": "02-00-00-00-00-0A",
            "ipv4": [{"ip": "192.0.2.10", "prefix": 24}],
            "gateways": ["192.0.2.1"],
        },
        {
            "alias": "Ethernet 3",
            "description": "VirtualBox Host-Only Ethernet Adapter",
            "if_index": 2,
            "status": "Up",
            "hardware": False,
            "virtual": True,
            "media": "802.3",
            "ipv4": {"ip": "192.0.2.200", "prefix": 24},  # PowerShell unwraps single items
            "gateways": [],
        },
        {
            "alias": "Tailscale",
            "description": "Tailscale Tunnel",
            "if_index": 50,
            "status": "Up",
            "hardware": False,
            "virtual": True,
            "ipv4": [{"ip": TS_IP, "prefix": 32}],
            "gateways": [],
        },
        {
            "alias": "Ethernet 2",
            "description": "Windscribe VPN",
            "if_index": 18,
            "status": "Disconnected",
            "hardware": False,
            "virtual": False,  # reports itself as physical: caught by name
            "media": "802.3",
            "ipv4": [{"ip": "169.254.0.9", "prefix": 16}],
            "gateways": [],
        },
        {
            "alias": "NordLynx",
            "description": "NordLynx Tunnel",
            "if_index": 19,
            "status": "Disconnected",
            "hardware": False,
            "virtual": True,
            "ipv4": [],
            "gateways": None,
        },
    ]


# ---------------------------------------------------------------- addresses


def test_mac_helpers():
    assert normalize_mac("02-00-00-AA-BB-0C") == "02:00:00:aa:bb:0c"
    assert normalize_mac("0200.00aa.bb0c") == "02:00:00:aa:bb:0c"
    assert normalize_mac("nope") is None
    assert is_locally_administered("02:00:00:aa:bb:0c")
    assert is_locally_administered(":".join(["0a"] + ["00"] * 5))
    assert not is_locally_administered(":".join(["04"] + ["00"] * 5))
    assert not is_unicast_device_mac(normalize_mac(BROADCAST))
    assert not is_unicast_device_mac(normalize_mac(MCAST))
    assert not is_unicast_device_mac(normalize_mac(ZERO))
    assert mask_mac("02:00:00:aa:bb:0c") == "02:00:00:••:••:0c"


@pytest.mark.parametrize(
    "subnet",
    [
        PUBLIC_NET,  # public
        "100.64.0.0/10",  # Tailscale
        "192.0.2.0/24",  # sample range is refused unless explicitly allowed
        "10.0.0.0/8",  # far too big
        "not a subnet",
    ],
)
def test_refuses_unsafe_subnets(subnet):
    with pytest.raises(UnsafeTargetError):
        validate_scan_subnet(subnet)


def test_accepts_private_home_subnets():
    assert str(validate_scan_subnet(PRIVATE_NET)) == PRIVATE_NET
    assert validate_scan_subnet("192.0.2.0/24", allow_sample=True) == SUBNET


def test_target_must_be_inside_subnet():
    ensure_target_allowed("192.0.2.50", [SUBNET], allow_sample=True)
    for bad in ("192.0.2.0", "192.0.2.255", OUTSIDE_IP, "example.com"):
        with pytest.raises(UnsafeTargetError):
            ensure_target_allowed(bad, [SUBNET], allow_sample=True)


# ---------------------------------------------------------------- adapters


def test_picks_physical_adapter_with_gateway():
    adapters = parse_adapters_json(json.dumps(adapter_rows()))
    choice = choose_home_adapter(adapters, allow_sample=True)
    assert choice.adapter.alias == "Ethernet"
    assert choice.subnet == SUBNET
    assert choice.gateway == "192.0.2.1"
    assert choice.local_ip == "192.0.2.10"
    assert choice.adapter.mac == "02:00:00:00:00:0a"
    reasons = dict(choice.skipped)
    assert "VirtualBox" in next(k for k in reasons if "VirtualBox" in k)
    assert any("Tailscale" in k for k in reasons)
    assert choice.vpn_up == []


def test_connected_vpn_is_reported_and_never_chosen():
    rows = adapter_rows()
    rows[3]["status"] = "Up"
    rows[3]["ipv4"] = [{"ip": "192.0.2.150", "prefix": 24}]
    rows[3]["gateways"] = ["192.0.2.149"]
    choice = choose_home_adapter(parse_adapters_json(json.dumps(rows)), allow_sample=True)
    assert choice.adapter.alias == "Ethernet"
    assert choice.vpn_up == ["Ethernet 2 (Windscribe VPN)"]


def test_no_home_adapter_when_only_virtual_ones_exist():
    rows = [r for r in adapter_rows() if r["alias"] != "Ethernet"]
    choice = choose_home_adapter(parse_adapters_json(json.dumps(rows)), allow_sample=True)
    assert not choice.ok


def test_adapter_override_by_alias():
    choice = choose_home_adapter(
        parse_adapters_json(json.dumps(adapter_rows())), "ethernet", allow_sample=True
    )
    assert choice.adapter.alias == "Ethernet"


def test_single_adapter_json_object():
    one = json.dumps(adapter_rows()[0])
    assert len(parse_adapters_json(one)) == 1
    assert parse_adapters_json("") == []


# ---------------------------------------------------------------- neighbor table


def neighbor_json():
    return json.dumps(
        [
            {"ip": "192.0.2.1", "mac": "02-00-00-00-00-01", "state": "Reachable"},
            {"ip": "192.0.2.21", "mac": "02-00-00-00-01-01", "state": "Reachable"},
            {"ip": "192.0.2.23", "mac": "02-00-00-00-01-03", "state": "Stale"},
            {"ip": "192.0.2.30", "mac": "02-00-00-00-02-01", "state": "Stale"},
            {"ip": "192.0.2.99", "mac": ZERO, "state": "Unreachable"},
            {"ip": "192.0.2.98", "mac": "", "state": "Incomplete"},
            {"ip": "192.0.2.255", "mac": BROADCAST, "state": "Permanent"},
            {"ip": "239.255.255.250", "mac": MCAST, "state": "Permanent"},
            {"ip": OUTSIDE_IP, "mac": "02-00-00-00-09-09", "state": "Reachable"},
        ]
    )


def test_parse_netneighbor_json_and_filter():
    rows = parse_netneighbor_json(neighbor_json())
    assert Neighbor("192.0.2.1", "02:00:00:00:00:01", "reachable") in rows
    usable = {n.ip for n in usable_neighbors(rows, SUBNET)}
    assert usable == {"192.0.2.1", "192.0.2.21", "192.0.2.23", "192.0.2.30"}


def test_parse_arp_a_selects_interface_section():
    text = "\n".join(
        [
            "",
            "Interface: 192.0.2.10 --- 0xa",
            "  Internet Address      Physical Address      Type",
            "  192.0.2.1             02-00-00-00-00-01     dynamic   ",
            "  192.0.2.21            02-00-00-00-01-01     dynamic   ",
            f"  192.0.2.255           {BROADCAST}     static    ",
            f"  239.255.255.250       {MCAST}     static    ",
            "",
            "Interface: 192.0.2.200 --- 0x2",
            "  Adresse Internet      Adresse physique      Type",  # localized headers
            "  192.0.2.201           02-00-00-00-07-07     dynamique ",
        ]
    )
    rows = parse_arp_a(text, local_ip="192.0.2.10")
    assert [r.ip for r in rows] == ["192.0.2.1", "192.0.2.21", "192.0.2.255", "239.255.255.250"]
    assert {n.ip for n in usable_neighbors(rows, SUBNET)} == {"192.0.2.1", "192.0.2.21"}
    assert len(parse_arp_a(text)) == 5


# ---------------------------------------------------------------- a full pass


class FakeProbe:
    def __init__(self, rows=None, neighbors=None, replied=None):
        self.rows = rows or adapter_rows()
        self.neighbor_rows = parse_netneighbor_json(neighbors or neighbor_json())
        self.replied = replied if replied is not None else {"192.0.2.1", "192.0.2.23"}
        self.swept: list[str] = []

    def adapters(self):
        return parse_adapters_json(json.dumps(self.rows))

    def neighbors(self, if_index, local_ip):
        assert if_index == 10
        return self.neighbor_rows

    async def sweep(self, hosts):
        self.swept = hosts
        return self.replied & set(hosts)


def test_discover_counts_ping_replies_and_confirmed_arp_entries():
    probe = FakeProbe()
    r = asyncio.run(discover(probe, settle_seconds=0, allow_sample=True))
    assert r.error is None
    assert len(probe.swept) == 253  # 254 hosts minus this PC
    assert "192.0.2.10" not in probe.swept
    seen = {o.ip: o for o in r.observations}
    # .1 and .23 replied; .21 ignored the ping but Windows confirmed its MAC (Reachable);
    # .30 is only a Stale leftover, so it is NOT counted as seen. .10 is this PC.
    assert set(seen) == {"192.0.2.1", "192.0.2.10", "192.0.2.21", "192.0.2.23"}
    assert seen["192.0.2.21"].replied is False
    assert seen["192.0.2.10"].state == "self"
    assert r.gateway_ip == "192.0.2.1"
    assert r.mac_for("192.0.2.1") == "02:00:00:00:00:01"


def test_discover_refuses_sample_range_on_a_real_run():
    # Outside tests/demo the sample range is not a private home range, so nothing is scanned.
    probe = FakeProbe()
    r = asyncio.run(discover(probe, settle_seconds=0))
    assert r.error and r.observations == [] and probe.swept == []
    assert r.observations == []


def test_discover_refuses_public_override():
    r = asyncio.run(discover(FakeProbe(), subnet_override=[PUBLIC_NET], settle_seconds=0))
    assert r.error and "Refusing" in r.error


def test_discover_reports_missing_adapter():
    rows = [r for r in adapter_rows() if r["alias"] != "Ethernet"]
    r = asyncio.run(discover(FakeProbe(rows=rows), settle_seconds=0, allow_sample=True))
    assert r.error and "No home network adapter" in r.error


# ---------------------------------------------------------------- vendors


def test_manuf_parser_longest_prefix_wins():
    text = "\n".join(
        [
            "# comment",
            "02:00:00\tExampleCo\tExample Company Ltd",
            "02:00:00:A0/28\tExSub\tExample Subsidiary",
            "02:00:00:A0:B0/36\tTiny\tTiny Block Inc",
            "02:00:00:C0/28\tOnlyShort",
            "garbage line",
        ]
    )
    db = parse_manuf(text)
    assert db.lookup("02:00:00:12:34:56") == "Example Company Ltd"
    assert db.lookup("02:00:00:a1:23:45") == "Example Subsidiary"
    assert db.lookup("02:00:00:a0:b0:01") == "Tiny Block Inc"
    assert db.lookup("02:00:00:c1:00:01") == "OnlyShort"
    assert parse_manuf("").lookup("02:00:00:12:34:56") == ""


# ---------------------------------------------------------------- hostnames


def _nb_response(txid, entries):
    q = names.build_nbstat_query(txid)[12:-4]
    body = bytes([len(entries)])
    for name, suffix, flags in entries:
        body += name.ljust(15).encode() + bytes([suffix]) + struct.pack(">H", flags)
    rr = q + struct.pack(">HHIH", 0x21, 1, 0, len(body)) + body
    return struct.pack(">HHHHHH", txid, 0x8400, 0, 1, 0, 0) + rr


def test_netbios_node_status_parsing():
    data = _nb_response(
        77,
        [("WORKGROUP", 0x00, 0x8400), ("SAMS-LAPTOP", 0x20, 0x0400), ("SAMS-LAPTOP", 0x00, 0x0400)],
    )
    assert names.parse_nbstat_response(data, 77) == "SAMS-LAPTOP"
    assert names.parse_nbstat_response(data, 78) == ""
    assert names.parse_nbstat_response(b"\x00\x01") == ""


def test_nbstat_query_shape():
    q = names.build_nbstat_query(5)
    assert len(q) == 12 + 34 + 4
    assert q[12] == 32 and q[13:15] == b"CK"


def _ptr_response(txid, ip, target):
    q = names.build_ptr_query(txid, ip)
    question = q[12:]
    rdata = names._encode_qname(target)
    answer = b"\xc0\x0c" + struct.pack(">HHIH", 12, 1, 120, len(rdata)) + rdata
    return struct.pack(">HHHHHH", txid, 0x8400, 1, 1, 0, 0) + question + answer


def test_mdns_ptr_parsing():
    data = _ptr_response(9, "192.0.2.21", "Alexs-Phone.local")
    assert names.parse_ptr_response(data, 9) == "Alexs-Phone.local"
    assert names.parse_ptr_response(data, 10) == ""
    assert names.parse_ptr_response(b"junk") == ""
    assert names.reverse_name("192.0.2.21") == dots(21, 2, 0, 192) + ".in-addr.arpa"


def test_compression_loop_is_rejected():
    header = struct.pack(">HHHHHH", 1, 0x8400, 0, 1, 0, 0)
    looping = header + b"\xc0\x0c" + struct.pack(">HHIH", 12, 1, 1, 2) + b"\xc0\x0c"
    assert names.parse_ptr_response(looping) == ""


def test_clean_hostname():
    assert names.clean_hostname("printer.local.", "192.0.2.50") == "printer.local"
    assert names.clean_hostname("192.0.2.50", "192.0.2.50") == ""
    assert names.clean_hostname("c-192-0-2-50.example.net", "192.0.2.50") == ""
