"""Pre-commit guard: keep real network and household data out of the repo.

Fails if any staged file, or the commit message, contains:

- a term from either deny list, both kept OUTSIDE the repo:
  ``%NETWATCH_DATA_DIR%\\denylist.txt`` (default ``C:\\NetWatchData``) and
  ``%BUDGET_DATA_DIR%\\denylist.txt`` (default ``C:\\BudgetData``).
  Terms are literal text (regex characters are escaped), case-insensitive,
  matched as whole tokens; whitespace inside a phrase matches any whitespace.
- a real-looking MAC address (anything outside the ``02:00:00`` sample range)
- a private IPv4 host address (10/8, 172.16/12, 192.168/16), a Tailscale
  address (100.64/10, fd7a:115c:a1e0::/48), or any public IPv4/IPv6 address
- a Tailscale (``*.ts.net``) or ISP DNS name (see ``ISP_DOMAINS``)
- a spreadsheet, database, capture, image, archive, or any binary file

Allowed on purpose: the range definitions themselves (10.0.0.0/8,
172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, fd7a:115c:a1e0::/48, fe80::/10),
127.0.0.1, and the sample range 192.0.2.0/24 with its addresses. Other
non-routable addresses (loopback, link-local, multicast groups, documentation)
are not identifying and are allowed.

Usage (wired up in .pre-commit-config.yaml):
    python scripts/check_private_data.py FILE [FILE ...]
    python scripts/check_private_data.py --commit-msg .git/COMMIT_EDITMSG

If a deny list is missing, the check FAILS, except in CI (``CI`` env var set),
where no private data exists to compare against. The pattern checks always run.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import sys
from pathlib import Path

BLOCKED_SUFFIXES = {
    ".xlsx",
    ".xls",
    ".xlsm",
    ".ods",
    ".csv",
    ".tsv",
    ".db",
    ".sqlite",
    ".sqlite3",
    ".bak",
    ".pdf",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".heic",
    ".zip",
    ".7z",
    ".pcap",
    ".pcapng",
    ".cap",
    ".gnmap",
    ".nmap",
}
BLOCKED_NAMES = {"config.toml", ".env", "manuf", "manuf.txt", "oui.txt"}
DATA_DIRS = (
    ("NETWATCH_DATA_DIR", r"C:\NetWatchData"),
    ("BUDGET_DATA_DIR", r"C:\BudgetData"),
)

# ---------------------------------------------------------------- patterns

SAMPLE_MAC_PREFIX = "020000"
_MAC = re.compile(
    r"(?<![0-9A-Fa-f:\-.])"
    r"(?:[0-9A-Fa-f]{2}([:\-])(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}"  # xx:xx:xx:xx:xx:xx
    r"|[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4})"  # xxxx.xxxx.xxxx
    r"(?![0-9A-Fa-f:\-]|\.[0-9A-Fa-f])"
)
_IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(/\d{1,2})?(?![\d.]*\d)")
_IPV6_CANDIDATE = re.compile(
    r"(?<![0-9A-Za-z:])([0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7})(?![0-9A-Za-z:])(/\d{1,3})?"
)
# ISP reverse-DNS suffixes. Some brand names are split in two so this file doesn't trip
# the deny list it enforces (they're on it, so they're blocked everywhere else).
ISP_DOMAINS = [
    "com" "cast.net",
    "com" "castbusiness.net",
    "xfin" "ity.com",
    "verizon.net",
    "att.net",
    "sbcglobal.net",
    "charter.com",
    "spectrum.net",
    "rr.com",
    "cox.net",
    "frontiernet.net",
]  # fmt: skip
_HOSTNAMES = re.compile(
    r"[A-Za-z0-9-]+\.(?:[A-Za-z0-9-]+\.)*(?:"
    + "|".join(re.escape(d) for d in ["ts.net", *ISP_DOMAINS])
    + r")\b",
    re.IGNORECASE,
)

ALLOWED_V4_DEFINITIONS = {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"}
ALLOWED_V6_DEFINITIONS = {"fd7a:115c:a1e0::/48", "fe80::/10", "2001:db8::/32"}
SAMPLE_V4 = ipaddress.IPv4Network("192.0.2.0/24")
BLOCKED_V4 = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("100.64.0.0/10"),
]
DOC_V6 = ipaddress.IPv6Network("2001:db8::/32")


def mac_problems(text: str) -> list[str]:
    out = []
    for m in _MAC.finditer(text):
        digits = re.sub(r"[^0-9A-Fa-f]", "", m.group(0)).lower()
        if not digits.startswith(SAMPLE_MAC_PREFIX):
            out.append(f"real-looking MAC address ({mask(m.group(0))})")
    return out


def ipv4_problems(text: str) -> list[str]:
    out = []
    for m in _IPV4.finditer(text):
        addr_s, prefix = m.group(1), m.group(2) or ""
        try:
            addr = ipaddress.IPv4Address(addr_s)
        except ValueError:
            continue  # e.g. 999.1.1.1, a version string
        if f"{addr_s}{prefix}" in ALLOWED_V4_DEFINITIONS:
            continue
        if addr in SAMPLE_V4 or addr_s == "127.0.0.1" or addr.is_multicast:
            continue  # multicast groups (e.g. SSDP's) are protocol constants
        if any(addr in net for net in BLOCKED_V4):
            out.append(f"private or Tailscale IPv4 address ({mask(addr_s)})")
        elif addr.is_global:
            out.append(f"public IPv4 address ({mask(addr_s)})")
    return out


def ipv6_problems(text: str) -> list[str]:
    out = []
    for m in _IPV6_CANDIDATE.finditer(text):
        addr_s, prefix = m.group(1), m.group(2) or ""
        if addr_s.count(":") < 2:
            continue
        try:
            addr = ipaddress.IPv6Address(addr_s)
        except ValueError:
            continue
        if f"{addr_s.lower()}{prefix}" in ALLOWED_V6_DEFINITIONS:
            continue
        if addr.is_loopback or addr.is_unspecified or addr.is_multicast or addr in DOC_V6:
            continue
        out.append(f"IPv6 address ({mask(addr_s)})")
    return out


def hostname_problems(text: str) -> list[str]:
    return [f"Tailscale or ISP host name ({mask(m.group(0))})" for m in _HOSTNAMES.finditer(text)]


def pattern_problems(text: str) -> list[str]:
    return mac_problems(text) + ipv4_problems(text) + ipv6_problems(text) + hostname_problems(text)


# ---------------------------------------------------------------- deny lists


def default_denylists() -> list[Path]:
    return [Path(os.environ.get(var, default)) / "denylist.txt" for var, default in DATA_DIRS]


def load_denylist(path: Path) -> list[str]:
    terms = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            terms.append(line)
    return terms


def compile_terms(terms: list[str]) -> list[tuple[str, re.Pattern[str]]]:
    """Literal, whole-token, case-insensitive patterns. Inner whitespace matches any whitespace."""
    out = []
    for term in terms:
        body = r"\s+".join(re.escape(p) for p in term.split())
        # Look-arounds instead of \b so terms that start or end with a symbol
        # (Wi-Fi names like "Home+5G-") still match as whole tokens.
        out.append((term, re.compile(rf"(?<![\w]){body}(?![\w])", re.IGNORECASE)))
    return out


def denylist_problems(text: str, patterns) -> list[str]:
    return [f"deny-listed term ({mask(term)})" for term, pat in patterns if pat.search(text)]


# ---------------------------------------------------------------- files


def is_binary(data: bytes) -> bool:
    return b"\x00" in data[:8192]


def check_text(text: str, patterns) -> list[str]:
    return denylist_problems(text, patterns) + pattern_problems(text)


def check_file(path: Path, patterns) -> list[str]:
    name = path.name.lower()
    if name in BLOCKED_NAMES or path.suffix.lower() in BLOCKED_SUFFIXES:
        return [f"{path}: file type is not allowed in this repo"]
    try:
        data = path.read_bytes()
    except OSError as exc:  # deleted/renamed files
        return [f"{path}: could not read ({exc})"] if path.exists() else []
    if is_binary(data):
        return [f"{path}: binary files are not allowed in this repo"]
    text = data.decode("utf-8", errors="replace")
    return [f"{path}: contains a {p}" for p in check_text(text, patterns)]


def mask(term: str) -> str:
    """Never echo a full private value into logs; show a hint only."""
    if len(term) <= 2:
        return "*" * len(term)
    return term[0] + "*" * (len(term) - 2) + term[-1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="*")
    parser.add_argument("--commit-msg", dest="commit_msg")
    parser.add_argument(
        "--denylist", action="append", help="deny list path (repeatable; overrides the defaults)"
    )
    args = parser.parse_args(argv)

    deny_paths = [Path(p) for p in args.denylist] if args.denylist else default_denylists()
    terms: list[str] = []
    for path in deny_paths:
        if path.exists():
            terms.extend(load_denylist(path))
        elif not os.environ.get("CI"):
            print(f"check_private_data: deny list not found at {path}. Refusing to continue.")
            return 1
    patterns = compile_terms(terms)

    problems: list[str] = []
    if args.commit_msg:
        text = Path(args.commit_msg).read_text(encoding="utf-8", errors="replace")
        text = "\n".join(ln for ln in text.splitlines() if not ln.startswith("#"))
        problems.extend(f"commit message: contains a {p}" for p in check_text(text, patterns))
    for f in args.files:
        problems.extend(check_file(Path(f), patterns))

    if problems:
        print("Private-data check FAILED:")
        for p in problems:
            print("  - " + p)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
