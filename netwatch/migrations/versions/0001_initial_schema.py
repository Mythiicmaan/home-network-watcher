"""initial schema

Revision ID: 0001
Revises:
Create Date: 2026-11-09 14:30:45.237012
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "device",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("mac", sa.String(length=17), nullable=False),
        sa.Column("is_randomized_mac", sa.Boolean(), nullable=False),
        sa.Column("vendor", sa.String(length=200), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=False),
        sa.Column("hostname_source", sa.String(length=20), nullable=False),
        sa.Column("names_checked_at", sa.DateTime(), nullable=True),
        sa.Column("friendly_name", sa.String(length=120), nullable=False),
        sa.Column("owner", sa.String(length=120), nullable=False),
        sa.Column("notes", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=10), nullable=False),
        sa.Column("first_seen", sa.DateTime(), nullable=False),
        sa.Column("last_seen", sa.DateTime(), nullable=False),
        sa.Column("last_ip", sa.String(length=45), nullable=False),
        sa.Column("is_gateway", sa.Boolean(), nullable=False),
        sa.Column("in_baseline", sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("mac"),
    )
    op.create_table(
        "scan_run",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=False),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
        sa.Column("hosts_found", sa.Integer(), nullable=False),
        sa.Column("ok", sa.Boolean(), nullable=False),
        sa.Column("degraded", sa.Boolean(), nullable=False),
        sa.Column("error", sa.Text(), nullable=False),
        sa.Column("subnet", sa.String(length=64), nullable=False),
        sa.Column("adapter", sa.String(length=255), nullable=False),
        sa.Column("gateway_ip", sa.String(length=45), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("scan_run", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_scan_run_started_at"), ["started_at"], unique=False)

    op.create_table(
        "setting",
        sa.Column("key", sa.String(length=100), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("key"),
    )
    op.create_table(
        "alert",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(length=30), nullable=False),
        sa.Column("dedup_key", sa.String(length=200), nullable=False),
        sa.Column("device_id", sa.Integer(), nullable=True),
        sa.Column("severity", sa.String(length=10), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("sent_ok", sa.Boolean(), nullable=False),
        sa.Column("sent_at", sa.DateTime(), nullable=True),
        sa.Column("send_attempts", sa.Integer(), nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=False),
        sa.Column("acknowledged", sa.Boolean(), nullable=False),
        sa.Column("acknowledged_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["device_id"], ["device.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("dedup_key"),
    )
    with op.batch_alter_table("alert", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_alert_created_at"), ["created_at"], unique=False)
        batch_op.create_index(batch_op.f("ix_alert_device_id"), ["device_id"], unique=False)
        batch_op.create_index(batch_op.f("ix_alert_kind"), ["kind"], unique=False)

    op.create_table(
        "port_scan",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("device_id", sa.Integer(), nullable=False),
        sa.Column("ip", sa.String(length=45), nullable=False),
        sa.Column("status", sa.String(length=10), nullable=False),
        sa.Column("reason", sa.String(length=20), nullable=False),
        sa.Column("method", sa.String(length=10), nullable=False),
        sa.Column("requested_at", sa.DateTime(), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
        sa.Column("open_ports", sa.JSON(), nullable=False),
        sa.Column("risky_ports", sa.JSON(), nullable=False),
        sa.Column("error", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(["device_id"], ["device.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("port_scan", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_port_scan_device_id"), ["device_id"], unique=False)

    op.create_table(
        "presence_hour",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("device_id", sa.Integer(), nullable=False),
        sa.Column("hour", sa.DateTime(), nullable=False),
        sa.Column("sightings", sa.Integer(), nullable=False),
        sa.Column("last_ip", sa.String(length=45), nullable=False),
        sa.ForeignKeyConstraint(["device_id"], ["device.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("device_id", "hour"),
    )
    op.create_table(
        "sighting",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("device_id", sa.Integer(), nullable=False),
        sa.Column("scan_run_id", sa.Integer(), nullable=True),
        sa.Column("ip", sa.String(length=45), nullable=False),
        sa.Column("seen_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["device_id"], ["device.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_run_id"], ["scan_run.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("sighting", schema=None) as batch_op:
        batch_op.create_index("ix_sighting_device_seen", ["device_id", "seen_at"], unique=False)
        batch_op.create_index(batch_op.f("ix_sighting_scan_run_id"), ["scan_run_id"], unique=False)
        batch_op.create_index(batch_op.f("ix_sighting_seen_at"), ["seen_at"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("sighting", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_sighting_seen_at"))
        batch_op.drop_index(batch_op.f("ix_sighting_scan_run_id"))
        batch_op.drop_index("ix_sighting_device_seen")

    op.drop_table("sighting")
    op.drop_table("presence_hour")
    with op.batch_alter_table("port_scan", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_port_scan_device_id"))

    op.drop_table("port_scan")
    with op.batch_alter_table("alert", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_alert_kind"))
        batch_op.drop_index(batch_op.f("ix_alert_device_id"))
        batch_op.drop_index(batch_op.f("ix_alert_created_at"))

    op.drop_table("alert")
    op.drop_table("setting")
    with op.batch_alter_table("scan_run", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_scan_run_started_at"))

    op.drop_table("scan_run")
    op.drop_table("device")
