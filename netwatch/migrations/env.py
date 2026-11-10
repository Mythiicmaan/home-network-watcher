"""Alembic environment. The engine is passed in by netwatch.db.migrate()."""

from alembic import context
from sqlalchemy import create_engine

from netwatch.models import Base

config = context.config
target_metadata = Base.metadata


def run_migrations() -> None:
    engine = config.attributes.get("engine")
    if engine is None:
        engine = create_engine(config.get_main_option("sqlalchemy.url"))
    with engine.connect() as connection:
        # Batch mode rebuilds a table by copying it, dropping the old one, and renaming.
        # With foreign keys on, that drop cascade-deletes every linked row (port checks,
        # sightings) and unlinks alerts. So foreign keys are off while migrating (SQLite
        # only allows changing this outside a transaction), checked, then turned back on.
        raw = connection.connection.dbapi_connection
        raw.execute("PRAGMA foreign_keys=OFF")
        try:
            context.configure(
                connection=connection,
                target_metadata=target_metadata,
                render_as_batch=True,  # SQLite needs batch mode for ALTER TABLE
                compare_type=True,
            )
            with context.begin_transaction():
                context.run_migrations()
                broken = connection.exec_driver_sql("PRAGMA foreign_key_check").fetchall()
                if broken:
                    raise RuntimeError(f"Migration left broken links: {broken[:5]}")
            connection.commit()
        finally:
            raw.execute("PRAGMA foreign_keys=ON")


run_migrations()
