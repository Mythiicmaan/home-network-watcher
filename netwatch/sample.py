"""The FAKE sample network used by tests, the demo database, and README screens.

Addresses come from 192.0.2.0/24 (TEST-NET-1, a documentation range that never
exists on a real network). MACs are locally administered ``02:00:00:xx:xx:xx``.
Names are made up.
"""

from __future__ import annotations

from dataclasses import dataclass

SAMPLE_SUBNET = "192.0.2.0/24"
SAMPLE_GATEWAY_IP = "192.0.2.1"
SAMPLE_HOST_IP = "192.0.2.10"  # "this desktop"


@dataclass(frozen=True)
class SampleDevice:
    mac: str
    ip: str
    vendor: str
    hostname: str
    friendly_name: str
    owner: str
    status: str  # unknown | known | ignored
    randomized: bool = False
    open_ports: tuple[int, ...] = ()


SAMPLE_DEVICES: list[SampleDevice] = [
    SampleDevice("02:00:00:00:00:01", SAMPLE_GATEWAY_IP, "Example Gateways Inc.", "gateway", "Gateway", "", "known", open_ports=(53, 80, 443)),
    SampleDevice("02:00:00:00:00:0a", SAMPLE_HOST_IP, "Example PC Parts", "desktop", "Home Desktop", "Alex", "known"),
    SampleDevice("02:00:00:00:01:01", "192.0.2.21", "", "", "Alex's Phone", "Alex", "known", randomized=True),
    SampleDevice("02:00:00:00:01:02", "192.0.2.22", "", "", "Sam's Phone", "Sam", "known", randomized=True),
    SampleDevice("02:00:00:00:01:03", "192.0.2.23", "Example Laptops Co.", "sams-laptop", "Sam's Laptop", "Sam", "known", open_ports=(445,)),
    SampleDevice("02:00:00:00:02:01", "192.0.2.30", "Example Displays", "living-room-tv", "Living Room TV", "", "known", open_ports=(8008, 8080)),
    SampleDevice("02:00:00:00:02:02", "192.0.2.40", "Microsoft", "game-console", "Game Console", "Kids", "known"),
    SampleDevice("02:00:00:00:02:03", "192.0.2.50", "Example Printers", "printer", "Office Printer", "", "known", open_ports=(80, 631, 9100)),
    SampleDevice("02:00:00:00:02:04", "192.0.2.60", "Example Smart Home", "", "Smart Plug", "", "ignored", open_ports=(23,)),
    SampleDevice("02:00:00:00:02:05", "192.0.2.61", "Example Smart Home", "", "Doorbell", "", "known"),
    SampleDevice("02:00:00:00:03:01", "192.0.2.77", "Example IoT Modules", "", "", "", "unknown", open_ports=(80, 1900)),
    SampleDevice("02:00:00:00:03:02", "192.0.2.88", "", "", "", "", "unknown", randomized=True),
]  # fmt: skip
