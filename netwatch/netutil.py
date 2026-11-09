"""Address helpers and the scan-safety rules.

The app only ever scans a private IPv4 subnet that it detected (or that the
owner configured). Anything else is refused here, in one place.
"""

from __future__ import annotations

import ipaddress
import re

PRIVATE_RANGES = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
]
TAILSCALE_V4 = ipaddress.IPv4Network("100.64.0.0/10")
TAILSCALE_V6 = ipaddress.IPv6Network("fd7a:115c:a1e0::/48")
LINK_LOCAL_V4 = ipaddress.IPv4Network("169.254.0.0/16")
# The documentation range used by the fake sample network. Allowed so the demo and
# tests work; it never exists on a real network.
SAMPLE_RANGE = ipaddress.IPv4Network("192.0.2.0/24")
MAX_PREFIX = 22  # refuse anything bigger than a /22 (1,022 hosts)

_HEX12 = re.compile(r"^[0-9a-f]{12}$")


class UnsafeTargetError(ValueError):
    """Raised when something asks to scan an address the app must not touch."""


def normalize_mac(value: str | None) -> str | None:
    """Return ``xx:xx:xx:xx:xx:xx`` (lowercase) or None if it isn't a MAC address."""
    if not value:
        return None
    digits = re.sub(r"[^0-9A-Fa-f]", "", value).lower()
    if not _HEX12.match(digits):
        return None
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2))


def mac_digits(mac: str) -> str:
    return mac.replace(":", "").lower()


def is_locally_administered(mac: str) -> bool:
    """Second hex digit 2, 6, A or E: a private/randomized address (e.g. iPhones)."""
    return bool(int(mac_digits(mac)[:2], 16) & 0b10)


def is_multicast_mac(mac: str) -> bool:
    return bool(int(mac_digits(mac)[:2], 16) & 0b01)


def is_unicast_device_mac(mac: str | None) -> bool:
    """A MAC that belongs to a real device (not empty, broadcast, or multicast)."""
    if not mac:
        return False
    digits = mac_digits(mac)
    if digits == "0" * 12 or digits == "f" * 12:
        return False
    return not is_multicast_mac(mac)


def mask_mac(mac: str) -> str:
    """Show the vendor half and hide the device half: ``aa:bb:cc:••:••:ff``."""
    parts = mac.split(":")
    if len(parts) != 6:
        return mac
    return ":".join(parts[:3] + ["••", "••", parts[5]])


def is_private_v4(addr: ipaddress.IPv4Address | ipaddress.IPv4Network) -> bool:
    if isinstance(addr, ipaddress.IPv4Network):
        return any(addr.subnet_of(r) for r in PRIVATE_RANGES)
    return any(addr in r for r in PRIVATE_RANGES)


def validate_scan_subnet(subnet: str | ipaddress.IPv4Network, *, allow_sample: bool = False):
    """Return the subnet as an IPv4Network, or raise UnsafeTargetError.

    Allowed: a private range (10/8, 172.16/12, 192.168/16), no bigger than a /22.
    The sample documentation range is allowed only when ``allow_sample`` is set.
    """
    try:
        net = ipaddress.IPv4Network(str(subnet), strict=False)
    except ValueError as exc:
        raise UnsafeTargetError(f"Not an IPv4 subnet: {subnet!r}") from exc
    if net.subnet_of(TAILSCALE_V4):
        raise UnsafeTargetError("Refusing to scan the Tailscale range.")
    sample_ok = allow_sample and net.subnet_of(SAMPLE_RANGE)
    if not (is_private_v4(net) or sample_ok):
        raise UnsafeTargetError(f"Refusing to scan {net}: not a private home range.")
    if net.prefixlen < MAX_PREFIX:
        raise UnsafeTargetError(
            f"Refusing to scan {net}: larger than a /{MAX_PREFIX}. Set network.subnets."
        )
    return net


def ensure_target_allowed(ip: str, subnets: list[ipaddress.IPv4Network], *, allow_sample=False):
    """Raise UnsafeTargetError unless ``ip`` is a host inside one of the allowed subnets."""
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError as exc:
        raise UnsafeTargetError(f"Not an IPv4 address: {ip!r}") from exc
    for net in subnets:
        validate_scan_subnet(net, allow_sample=allow_sample)
        if addr in net and addr not in (net.network_address, net.broadcast_address):
            return addr
    raise UnsafeTargetError(f"{ip} is outside the configured home subnet.")


def scan_hosts(net: ipaddress.IPv4Network) -> list[str]:
    return [str(h) for h in net.hosts()]
