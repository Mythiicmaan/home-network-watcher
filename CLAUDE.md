# CLAUDE.md: home-network-watcher

A self-hosted home network monitor: finds every device on the home network, keeps an inventory, alerts a phone when a new device appears, checks new devices for risky open ports, and flags signs of ARP spoofing or IP conflicts. It runs 24/7 on a Windows 10 desktop and is reached from phones over Tailscale.

## Read first
- The full spec lives **outside this repo** at `%NETWATCH_DATA_DIR%\PLAN.md` (default `C:\NetWatchData\PLAN.md`). Read it before starting work.
- **That file and everything in `C:\NetWatchData\` is private.** Never copy real MAC addresses, IP addresses, hostnames, device names, Wi-Fi names, Tailscale names, people's names, or alert keys into this repo, including code, comments, tests, fixtures, docs, commit messages, and screenshots.
- Use only the fake sample network: **192.0.2.0/24** IPs and **`02:00:00:xx:xx:xx`** MACs, with made-up names like "Alex's Phone."
- A sister project lives at `C:\Projects\household-budget`. Reuse its patterns (install scripts, auth, backups, privacy hook, README style) by **copying and adapting**. Never modify that project.

## Stack
Python 3.12 · FastAPI + Uvicorn (bound to `127.0.0.1:8766` only) · Jinja2 + HTMX · SQLite via SQLAlchemy 2.x + Alembic · pytest · Ruff · GitHub Actions · Nmap (TCP connect scans only)

## Rules
- Only ever scan the configured private subnet. Refuse public ranges.
- Never send spoofed or malicious traffic. Prove the detection rules with simulated data in tests.
- Discovery must work as a **standard, non-admin** account: ping sweep plus the Windows neighbor table.
- Auto-detect the home subnet from the physical adapter that has a default gateway. Ignore VPN, Tailscale, and virtual (e.g. VirtualBox) adapters. A scan that looks broken (e.g. a VPN is connected) is marked **degraded** and must never mark devices offline or fire alerts.
- Alerts fire once per event. Failures to send are surfaced loudly and retried, never silent.
- All paths come from `NETWATCH_DATA_DIR`. Secrets and household settings live in `config.toml`, never in source.
- Write tests for discovery parsing and detection rules before building the UI. Keep `pytest` and `ruff` green.
- Don't break the budget app: keep port 8765 and its `tailscale serve` on 443 untouched. This app uses 8766 and Tailscale HTTPS port 8443.

## Privacy guardrails (don't weaken these)
- `.gitignore` blocks databases, `config.toml`, logs, CSVs, `.env`, and the vendor (OUI) cache.
- Pre-commit runs `gitleaks` and a privacy check. The check reads both deny lists from outside the repo and blocks real-looking MACs (outside `02:00:00`), private-range IPs (10/8, 172.16/12, 192.168/16), Tailscale IPs (100.64/10, fd7a:115c:a1e0::/48), public IPv4/IPv6 addresses, `*.ts.net` and ISP DNS names, spreadsheets, and binaries, in files and commit messages. (Exceptions: the range definitions themselves, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10`, plus `127.0.0.1` and the sample range `192.0.2.0/24` with its addresses, may appear in code and docs. Block specific host addresses, not the ranges.)
- The repo stays **private** until the owner reviews it and makes it public.

## Working style
- Follow the phases in the private plan in order. Use a task list and commit after each meaningful step.
- When a step needs the owner (admin/UAC prompts, the Gmail app password, naming devices, the service account password, reviewing the repo), **stop and say exactly what's needed.** Don't work around it.
- Finish each session with: what was built, open questions, and the repo URL.
