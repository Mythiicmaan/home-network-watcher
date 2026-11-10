"""Command line entry point.

python -m netwatch                 run the app + monitor on 127.0.0.1:8766 (what the task runs)
python -m netwatch scan            run one discovery pass now and record it
python -m netwatch set-pin         set or change the shared PIN
python -m netwatch migrate         apply database migrations
python -m netwatch test-alert      send a test email through the configured alert channel
python -m netwatch sample-data     fill the data folder's database with the FAKE sample network
python -m netwatch --sample        demo server on sample data (no scanning)
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

HOST = "127.0.0.1"  # never listen on the LAN; phones come in through Tailscale
PORT = 8766


def log_config(logs_dir: Path) -> dict:
    """Uvicorn + app logging to the console and to logs/app.log (rotated, 5 x 2 MB)."""
    logs_dir.mkdir(parents=True, exist_ok=True)
    handler = {
        "class": "logging.handlers.RotatingFileHandler",
        "filename": str(logs_dir / "app.log"),
        "maxBytes": 2_000_000,
        "backupCount": 5,
        "encoding": "utf-8",
        "formatter": "plain",
    }
    return {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {"plain": {"format": "%(asctime)s %(levelname)s %(name)s: %(message)s"}},
        "handlers": {
            "file": handler,
            "console": {"class": "logging.StreamHandler", "formatter": "plain"},
        },
        "loggers": {
            "uvicorn": {"handlers": ["file", "console"], "level": "INFO", "propagate": False},
            "uvicorn.error": {"level": "INFO"},
            "uvicorn.access": {"handlers": ["file"], "level": "WARNING", "propagate": False},
            "netwatch": {"handlers": ["file", "console"], "level": "INFO", "propagate": False},
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m netwatch")
    parser.add_argument(
        "command",
        nargs="?",
        default="serve",
        choices=["serve", "scan", "set-pin", "migrate", "sample-data", "test-alert"],
    )
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--sample", action="store_true", help="demo on sample data, no scanning")
    args = parser.parse_args(argv)

    if args.sample:
        os.environ["NETWATCH_SAMPLE"] = "1"
        # Never mix the demo with real data: default to the git-ignored data/sample folder.
        os.environ.setdefault("NETWATCH_DATA_DIR", str(Path.cwd() / "data" / "sample"))

    from netwatch.config import DEFAULT_DATA_DIR, load_config
    from netwatch.db import make_engine, make_sessionmaker, migrate, session_scope

    cfg = load_config()
    if args.command == "sample-data" and cfg.paths.data_dir == Path(DEFAULT_DATA_DIR):
        print("Refusing to put sample data in the real data folder. Set NETWATCH_DATA_DIR.")
        return 1

    if args.command == "serve":
        import uvicorn

        if args.sample:
            main(["sample-data"])
        uvicorn.run(
            "netwatch.app:app",
            host=HOST,
            port=args.port,
            proxy_headers=False,
            log_config=log_config(cfg.paths.logs),
        )
        return 0

    if args.command == "test-alert":
        from netwatch.alerts.dispatch import send_test_alert

        ok, detail = send_test_alert(cfg)
        print(
            "Test alert sent. Check your inbox (and spam)."
            if ok
            else f"Test alert FAILED: {detail}"
        )
        return 0 if ok else 1

    engine = make_engine(cfg.paths.db)
    migrate(engine)
    factory = make_sessionmaker(engine)

    if args.command == "migrate":
        print(f"Database is up to date: {cfg.paths.db}")
        return 0

    if args.command == "sample-data":
        from netwatch.sample_data import build_sample_db
        from netwatch.timeutil import utcnow

        with session_scope(factory) as s:
            build_sample_db(s, utcnow())
        print(f"Sample network ready in {cfg.paths.db}")
        return 0

    if args.command == "scan":
        import asyncio
        import logging.config

        from netwatch.monitor import Monitor

        logging.config.dictConfig(log_config(cfg.paths.logs))

        async def once():
            mon = Monitor(cfg, factory)
            await mon.load_vendors()
            return mon, await mon.scan_once()

        mon, report = asyncio.run(once())
        res = mon.state.last_result
        h = report.health
        state = "FAILED" if not h.ok else ("DEGRADED" if h.degraded else "ok")
        print(f"Scan {state}: {len(res.observations)} devices on {len(res.subnets)} subnet(s).")
        if h.reason:
            print(f"  {h.reason}")
        print(
            f"  New devices: {len(report.new_device_ids)}"
            f"{' (first scan: saved as the baseline, no alerts)' if report.baseline else ''}"
            f", alerts: {len(report.alert_ids)}, port checks queued: {report.port_scans_queued}"
        )
        engine.dispose()
        return 0 if h.ok else 1

    from netwatch import auth

    pin = getpass.getpass("New PIN (4-12 digits): ")
    if pin != getpass.getpass("Repeat PIN: "):
        print("PINs don't match.")
        return 1
    try:
        with session_scope(factory) as s:
            auth.set_pin(s, pin)
    except ValueError as exc:
        print(exc)
        return 1
    print("PIN saved. Restart the app so phones are asked to sign in again.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
