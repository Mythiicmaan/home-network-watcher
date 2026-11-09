# Home Network Watcher

A small, self-hosted monitor for a home network. It runs 24/7 on a Windows desktop and:

- finds every device on the home network every few minutes (no admin rights, no drivers)
- keeps an inventory: MAC, IP, hostname, vendor, first and last seen, plus a friendly name and owner
- alerts when a never-before-seen device joins
- checks new devices for risky open ports (TCP connect scan)
- flags signs of trouble: the gateway's MAC changing (possible ARP spoofing, MITRE ATT&CK T1557.002) and IP conflicts
- shows it all on a phone-friendly dashboard, reached over Tailscale

> Work in progress. All examples use a fake sample network (`192.0.2.0/24`, MACs `02:00:00:xx:xx:xx`).

## Development

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[dev]"
.\.venv\Scripts\pre-commit install
.\.venv\Scripts\python -m pytest
.\.venv\Scripts\ruff check .
```
