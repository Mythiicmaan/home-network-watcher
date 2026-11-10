"""The Alembic migrations build exactly the schema the models describe."""

from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext

from netwatch.models import Base


def test_migrations_match_models(engine):
    with engine.connect() as conn:
        ctx = MigrationContext.configure(conn, opts={"compare_type": True})
        diff = compare_metadata(ctx, Base.metadata)
    assert diff == []


def test_upgrading_keeps_rows_linked_to_rebuilt_tables(tmp_path):
    """SQLite batch migrations rebuild a table (copy, drop, rename). With foreign keys on,
    dropping the old device table would cascade-delete port checks and sightings and
    unlink alerts. Migrations must run with foreign keys off, then turn them back on."""
    from alembic import command
    from sqlalchemy import text

    from netwatch.db import alembic_config, make_engine, migrate

    engine = make_engine(tmp_path / "old.db")
    command.upgrade(alembic_config(engine), "0001")
    with engine.begin() as conn:
        conn.execute(
            text(
                "insert into device (id, mac, is_randomized_mac, vendor, hostname, "
                "hostname_source, friendly_name, owner, notes, status, first_seen, last_seen, "
                "last_ip, is_gateway, in_baseline) values (1, '02:00:00:00:00:0a', 0, '', '', "
                "'', 'Home Desktop', '', '', 'known', '2026-01-01', '2026-01-01', "
                "'192.0.2.10', 0, 1)"
            )
        )
        conn.execute(
            text(
                "insert into scan_run (id, started_at, hosts_found, ok, degraded, error, "
                "subnet, adapter, gateway_ip) values (1, '2026-01-01', 1, 1, 0, '', '', '', '')"
            )
        )
        conn.execute(
            text(
                "insert into sighting (device_id, scan_run_id, ip, seen_at) "
                "values (1, 1, '192.0.2.10', '2026-01-01')"
            )
        )
        conn.execute(
            text(
                "insert into port_scan (device_id, ip, status, reason, method, requested_at, "
                "open_ports, risky_ports, error) values (1, '192.0.2.10', 'done', 'baseline', "
                "'nmap', '2026-01-01', '[]', '[]', '')"
            )
        )
        conn.execute(
            text(
                "insert into alert (kind, dedup_key, device_id, severity, title, message, "
                "details, created_at, sent_ok, send_attempts, last_error, acknowledged) values "
                "('risky_port', 'risky_port:1:445', 1, 'warning', 't', 'm', '{}', "
                "'2026-01-01', 1, 1, '', 0)"
            )
        )

    migrate(engine)

    with engine.connect() as conn:
        assert conn.scalar(text("select count(*) from sighting")) == 1
        assert conn.scalar(text("select count(*) from port_scan")) == 1
        assert conn.scalar(text("select device_id from alert")) == 1
        assert conn.scalar(text("select is_this_pc from device")) == 0
        # Foreign keys are back on for the connection the migration used.
        assert conn.scalar(text("pragma foreign_keys")) == 1
    engine.dispose()
