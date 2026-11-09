"""Shared fixtures. Everything here uses the FAKE sample network (192.0.2.0/24)."""

from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta

import pytest

from netwatch.db import make_engine, make_sessionmaker, migrate
from netwatch.discovery.adapters import Adapter, AdapterChoice
from netwatch.discovery.oui import parse_manuf
from netwatch.discovery.scan import DiscoveryResult, Observation
from netwatch.sample import SAMPLE_GATEWAY_IP, SAMPLE_HOST_IP, SAMPLE_SUBNET

T0 = datetime(2027, 1, 4, 12, 0, 0)  # a Monday, naive UTC
GW_MAC = "02:00:00:00:00:01"
EVIL_MAC = "02:00:00:00:0e:01"

# A tiny fake vendor list: 02:00:00:00:00:xx is the "gateway vendor", 02:00:00:00:02:xx "smart home".
VENDORS = parse_manuf(
    "02:00:00:00:00:00/40\tExGw\tExample Gateways Inc.\n"
    "02:00:00:00:02:00/40\tExHome\tExample Smart Home\n"
)


@pytest.fixture
def engine(tmp_path):
    eng = make_engine(tmp_path / "netwatch.db")
    migrate(eng)
    yield eng
    eng.dispose()


@pytest.fixture
def s(engine):
    factory = make_sessionmaker(engine)
    session = factory()
    yield session
    session.close()


def choice() -> AdapterChoice:
    adapter = Adapter(
        alias="Ethernet",
        description="Example PCIe GbE Controller",
        if_index=10,
        status="Up",
        hardware=True,
        virtual=False,
        media="802.3",
        mac="02:00:00:00:00:0a",
        ipv4=[(SAMPLE_HOST_IP, 24)],
        gateways=[SAMPLE_GATEWAY_IP],
    )
    return AdapterChoice(
        adapter,
        ipaddress.IPv4Network(SAMPLE_SUBNET),
        SAMPLE_GATEWAY_IP,
        SAMPLE_HOST_IP,
    )


def scan(ip_to_mac: dict[str, str], at: datetime, *, vpn_up=None, error=None) -> DiscoveryResult:
    """A simulated discovery pass."""
    c = choice()
    c.vpn_up = list(vpn_up or [])
    return DiscoveryResult(
        started_at=at,
        finished_at=at + timedelta(seconds=15),
        choice=c,
        subnets=[c.subnet],
        observations=[Observation(ip, mac, True, "reachable") for ip, mac in ip_to_mac.items()],
        error=error,
    )


# The sample household on a normal day.
HOME = {
    SAMPLE_GATEWAY_IP: GW_MAC,
    SAMPLE_HOST_IP: "02:00:00:00:00:0a",
    "192.0.2.21": "02:00:00:00:01:01",
    "192.0.2.22": "02:00:00:00:01:02",
    "192.0.2.30": "02:00:00:00:02:01",
    "192.0.2.40": "02:00:00:00:02:02",
    "192.0.2.50": "02:00:00:00:02:03",
    "192.0.2.60": "02:00:00:00:02:04",
    "192.0.2.61": "02:00:00:00:02:05",
    "192.0.2.62": "02:00:00:00:02:06",
}
