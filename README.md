# Home Network Watcher

A small, self-hosted monitor for a home network. It runs 24/7 on a Windows desktop and:

- finds every device on the home network every few minutes (no admin rights, no drivers)
- keeps an inventory: MAC, IP, hostname, vendor, first and last seen, plus a friendly name and owner
- alerts when a never-before-seen device joins
- checks new devices for risky open ports (TCP connect scan)
- flags signs of trouble: the gateway's MAC changing (possible ARP spoofing, MITRE ATT&CK T1557.002) and IP conflicts
- shows it all on a phone-friendly dashboard, reached over Tailscale

> Work in progress. All examples use a fake sample network (`192.0.2.0/24`, MACs `02:00:00:xx:xx:xx`).

## Run it on the home PC

```powershell
.\.venv\Scripts\python -m netwatch           # app + monitor on http://localhost:8766
.\.venv\Scripts\python -m netwatch scan      # one discovery pass, prints counts only
.\.venv\Scripts\python -m netwatch --sample  # demo on the fake sample network, no scanning
```

Data lives in `%NETWATCH_DATA_DIR%` (default `C:\NetWatchData`): the database, `config.toml`
(copy `config.example.toml`), logs, and the downloaded vendor list. The first good scan is a
silent baseline; after that, every never-seen device raises one alert.

## Run it 24/7

From an **admin** PowerShell window, once:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install.ps1
```

It creates a standard (non-admin) account `netwatchsvc` and a scheduled task that starts the
app at boot, before anyone signs in, and restarts it if it crashes. It gives that account
Modify rights on the data and backup folders only. It also makes a first backup, waits for a
first scan as the service account, and sets up phone access:
`tailscale serve --bg --https=8443 http://127.0.0.1:8766`. If another app is already served
on HTTPS port 443, it's checked before and after and left as it was.

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\check_service.ps1   # status (no admin needed)
powershell -ExecutionPolicy Bypass -File .\scripts\restart.ps1         # pick up new code
powershell -ExecutionPolicy Bypass -File .\scripts\restore.ps1 <backup .db file>
powershell -ExecutionPolicy Bypass -File .\scripts\uninstall.ps1       # undo (data untouched)
```

**Backups** run nightly at 2:30 AM to `[backup] dir` in `config.toml`, using SQLite's online
backup API. Each copy is integrity-checked; 30 daily and 12 monthly copies are kept. If the
drive is missing, nothing is written anywhere else: the app shows a banner, `/health` reports
it, one email goes out per day, and it retries hourly. **Back up now** is in Settings.
Database migrations run with SQLite foreign keys off, so rebuilding a table never
cascade-deletes linked rows.

## Development

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[dev]"
.\.venv\Scripts\pre-commit install
.\.venv\Scripts\python -m pytest
.\.venv\Scripts\ruff check .
```
