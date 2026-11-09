"""Tests for the pre-commit privacy check.

Values the check must BLOCK are built at runtime (e.g. ``dots(10, 0, 0, 5)``) so that
this file itself never contains one and passes the check.
"""

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("cpd", ROOT / "scripts" / "check_private_data.py")
cpd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cpd)


def dots(*parts) -> str:
    return ".".join(str(p) for p in parts)


def colons(*parts) -> str:
    return ":".join(str(p) for p in parts)


def write_denylist(tmp_path: Path) -> Path:
    p = tmp_path / "denylist.txt"
    p.write_text("# comment\n\nZorblax\nHome+Net 5G-\nDESKTOP-FAKE99\n", encoding="utf-8")
    return p


def run(tmp_path: Path, text: str, name: str = "a.py") -> int:
    deny = write_denylist(tmp_path)
    f = tmp_path / name
    f.write_text(text, encoding="utf-8")
    return cpd.main([str(f), "--denylist", str(deny)])


# ---------------------------------------------------------------- deny list


def test_denylist_case_insensitive_whole_words(tmp_path):
    assert run(tmp_path, "owner = 'zorblax'\n") == 1
    assert run(tmp_path, "x = 'Zorblaxian'\n") == 0


def test_denylist_terms_with_regex_symbols_are_literal(tmp_path):
    assert run(tmp_path, "ssid: home+net   5g-\n") == 1
    assert run(tmp_path, "ssid: homeenet 5g\n") == 0  # '+' is not a regex quantifier
    assert run(tmp_path, "pc = desktop-fake99.local\n") == 1


def test_both_default_denylists_are_read(tmp_path, monkeypatch):
    nw, hb = tmp_path / "nw", tmp_path / "hb"
    nw.mkdir()
    hb.mkdir()
    (nw / "denylist.txt").write_text("Alpha\n", encoding="utf-8")
    (hb / "denylist.txt").write_text("Bravo\n", encoding="utf-8")
    monkeypatch.setenv("NETWATCH_DATA_DIR", str(nw))
    monkeypatch.setenv("BUDGET_DATA_DIR", str(hb))
    f = tmp_path / "a.md"
    f.write_text("bravo was here\n", encoding="utf-8")
    assert cpd.main([str(f)]) == 1
    f.write_text("alpha was here\n", encoding="utf-8")
    assert cpd.main([str(f)]) == 1
    f.write_text("charlie was here\n", encoding="utf-8")
    assert cpd.main([str(f)]) == 0


def test_missing_denylist_fails_closed_outside_ci(tmp_path, monkeypatch):
    monkeypatch.delenv("CI", raising=False)
    f = tmp_path / "a.py"
    f.write_text("ok\n", encoding="utf-8")
    assert cpd.main([str(f), "--denylist", str(tmp_path / "missing.txt")]) == 1
    monkeypatch.setenv("CI", "true")
    assert cpd.main([str(f), "--denylist", str(tmp_path / "missing.txt")]) == 0


# ---------------------------------------------------------------- MAC addresses


@pytest.mark.parametrize(
    "mac",
    [
        colons("a4", "83", "e7", "12", "34", "56"),
        "-".join(["A4", "83", "E7", "12", "34", "56"]),
        dots("a483", "e712", "3456"),
        colons(
            "02", "00", "01", "12", "34", "56"
        ),  # locally administered, but not the sample range
    ],
)
def test_blocks_real_looking_macs(tmp_path, mac):
    assert run(tmp_path, f"mac = '{mac}'\n") == 1


def test_allows_sample_macs_and_lookalikes(tmp_path):
    text = (
        "a = '02:00:00:aa:bb:01'\n"
        "b = '02-00-00-AA-BB-02'\n"
        "t = '12:30:45'\n"  # a time
        "h = 'deadbeefcafe'\n"  # bare hex is not a MAC
    )
    assert run(tmp_path, text) == 0


# ---------------------------------------------------------------- IPv4


@pytest.mark.parametrize(
    "ip",
    [
        dots(10, 0, 0, 5),
        dots(172, 20, 1, 1),
        dots(192, 168, 1, 10),
        dots(100, 90, 1, 2),  # Tailscale CGNAT
        dots(8, 8, 8, 8),  # public
        dots(73, 1, 2, 3) + "/24",
        dots(10, 0, 0, 0) + "/24",  # a specific home subnet is not an allowed definition
    ],
)
def test_blocks_private_tailscale_and_public_ipv4(tmp_path, ip):
    assert run(tmp_path, f"ip = '{ip}'\n") == 1


def test_allows_range_definitions_sample_and_loopback(tmp_path):
    text = (
        "PRIVATE = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']\n"
        "TAILSCALE = '100.64.0.0/10'\n"
        "SAMPLE = '192.0.2.0/24'\n"
        "router = '192.0.2.1'\n"
        "host = '127.0.0.1'\n"
        "mask = '255.255.255.0'\n"
        "apipa = '169.254.10.20'\n"
        "version = 'nmap 7.99'\n"
    )
    assert run(tmp_path, text) == 0


# ---------------------------------------------------------------- IPv6 and names


def test_blocks_ipv6_addresses(tmp_path):
    assert run(tmp_path, "a = '" + colons("2601", "abc", "1", "2", "", "1") + "'\n") == 1
    assert run(tmp_path, "a = '" + colons("fd7a", "115c", "a1e0", "", "1") + "'\n") == 1
    assert run(tmp_path, "a = '" + colons("fe80", "", "1c2b", "3d4e", "5f60", "7a8b") + "'\n") == 1


def test_allows_ipv6_definitions_and_non_addresses(tmp_path):
    text = (
        "TS6 = 'fd7a:115c:a1e0::/48'\n"
        "LL = 'fe80::/10'\n"
        "lo = '::1'\n"
        "doc = '2001:db8::5'\n"
        ".card a::before { content: '' }\n"
        "std::vector\n"
    )
    assert run(tmp_path, text) == 0


def test_blocks_tailscale_and_isp_hostnames(tmp_path):
    assert run(tmp_path, "url = 'https://box." + "tail1234." + "ts.net:8443'\n") == 1
    assert run(tmp_path, "ptr = 'c-1-2-3-4.hsd1.ga." + "com" + "cast.net'\n") == 1
    ok = "allowed = h.endswith('.ts.net')  # https://<pc>.<tailnet>.ts.net\n"
    assert run(tmp_path, ok) == 0


# ---------------------------------------------------------------- files and messages


def test_blocks_spreadsheets_captures_and_binaries(tmp_path):
    for name in ("x.xlsx", "devices.csv", "cap.pcapng", "config.toml", "manuf"):
        assert run(tmp_path, "not really", name=name) == 1
    deny = write_denylist(tmp_path)
    binf = tmp_path / "blob.dat"
    binf.write_bytes(b"abc\x00def")
    assert cpd.main([str(binf), "--denylist", str(deny)]) == 1


def test_commit_message_checked(tmp_path):
    deny = write_denylist(tmp_path)
    msg = tmp_path / "COMMIT_EDITMSG"
    msg.write_text("Fix scan of " + dots(192, 168, 0, 7) + "\n", encoding="utf-8")
    assert cpd.main(["--commit-msg", str(msg), "--denylist", str(deny)]) == 1
    msg.write_text("Add thing for Zorblax\n", encoding="utf-8")
    assert cpd.main(["--commit-msg", str(msg), "--denylist", str(deny)]) == 1
    msg.write_text("Add thing\n# zorblax in a git comment line is ignored\n", encoding="utf-8")
    assert cpd.main(["--commit-msg", str(msg), "--denylist", str(deny)]) == 0


def test_problem_messages_mask_the_value(tmp_path, capsys):
    secret_ip = dots(10, 1, 2, 3)
    run(tmp_path, f"ip = '{secret_ip}'\n")
    out = capsys.readouterr().out
    assert secret_ip not in out
