"""Database tables (SQLite via SQLAlchemy 2.x). Times are naive UTC."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from netwatch.timeutil import utcnow

DEVICE_STATUSES = ("unknown", "known", "ignored")
ALERT_KINDS = ("new_device", "gateway_mac_change", "ip_conflict", "risky_port", "digest")


class Base(DeclarativeBase):
    pass


class Device(Base):
    __tablename__ = "device"

    id: Mapped[int] = mapped_column(primary_key=True)
    mac: Mapped[str] = mapped_column(String(17), unique=True)
    is_randomized_mac: Mapped[bool] = mapped_column(Boolean, default=False)
    vendor: Mapped[str] = mapped_column(String(200), default="")
    hostname: Mapped[str] = mapped_column(String(255), default="")
    hostname_source: Mapped[str] = mapped_column(String(20), default="")
    names_checked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    friendly_name: Mapped[str] = mapped_column(String(120), default="")
    owner: Mapped[str] = mapped_column(String(120), default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(10), default="unknown")
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_ip: Mapped[str] = mapped_column(String(45), default="")
    is_gateway: Mapped[bool] = mapped_column(Boolean, default=False)
    in_baseline: Mapped[bool] = mapped_column(Boolean, default=False)

    sightings: Mapped[list[Sighting]] = relationship(back_populates="device")
    port_scans: Mapped[list[PortScan]] = relationship(
        back_populates="device", order_by="PortScan.id.desc()"
    )

    @property
    def display_name(self) -> str:
        return self.friendly_name or self.hostname or self.vendor or "Unnamed device"


class Sighting(Base):
    __tablename__ = "sighting"
    __table_args__ = (Index("ix_sighting_device_seen", "device_id", "seen_at"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("device.id", ondelete="CASCADE"))
    scan_run_id: Mapped[int | None] = mapped_column(
        ForeignKey("scan_run.id", ondelete="SET NULL"), nullable=True, index=True
    )
    ip: Mapped[str] = mapped_column(String(45))
    seen_at: Mapped[datetime] = mapped_column(DateTime, index=True)

    device: Mapped[Device] = relationship(back_populates="sightings")


class PresenceHour(Base):
    """Sightings older than 30 days, rolled up to one row per device per hour."""

    __tablename__ = "presence_hour"
    __table_args__ = (UniqueConstraint("device_id", "hour"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("device.id", ondelete="CASCADE"))
    hour: Mapped[datetime] = mapped_column(DateTime)
    sightings: Mapped[int] = mapped_column(Integer, default=0)
    last_ip: Mapped[str] = mapped_column(String(45), default="")


class ScanRun(Base):
    __tablename__ = "scan_run"

    id: Mapped[int] = mapped_column(primary_key=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    hosts_found: Mapped[int] = mapped_column(Integer, default=0)
    ok: Mapped[bool] = mapped_column(Boolean, default=False)
    degraded: Mapped[bool] = mapped_column(Boolean, default=False)
    error: Mapped[str] = mapped_column(Text, default="")
    subnet: Mapped[str] = mapped_column(String(64), default="")
    adapter: Mapped[str] = mapped_column(String(255), default="")
    gateway_ip: Mapped[str] = mapped_column(String(45), default="")


class PortScan(Base):
    __tablename__ = "port_scan"

    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("device.id", ondelete="CASCADE"), index=True)
    ip: Mapped[str] = mapped_column(String(45), default="")
    status: Mapped[str] = mapped_column(String(10), default="queued")  # queued|running|done|failed
    reason: Mapped[str] = mapped_column(String(20), default="new")  # new | manual | baseline
    method: Mapped[str] = mapped_column(String(10), default="")  # nmap | builtin
    requested_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    open_ports: Mapped[list] = mapped_column(JSON, default=list)
    risky_ports: Mapped[list] = mapped_column(JSON, default=list)
    error: Mapped[str] = mapped_column(Text, default="")

    device: Mapped[Device] = relationship(back_populates="port_scans")


class Alert(Base):
    __tablename__ = "alert"

    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(30), index=True)
    # One alert per event: e.g. "new_device:<mac>", "risky_port:<device>:<port>".
    dedup_key: Mapped[str] = mapped_column(String(200), unique=True)
    device_id: Mapped[int | None] = mapped_column(
        ForeignKey("device.id", ondelete="SET NULL"), nullable=True, index=True
    )
    severity: Mapped[str] = mapped_column(String(10), default="info")  # info | warning | high
    title: Mapped[str] = mapped_column(String(200), default="")
    message: Mapped[str] = mapped_column(Text, default="")
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    sent_ok: Mapped[bool] = mapped_column(Boolean, default=False)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    send_attempts: Mapped[int] = mapped_column(Integer, default=0)
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_error: Mapped[str] = mapped_column(Text, default="")
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    device: Mapped[Device | None] = relationship()


class Setting(Base):
    __tablename__ = "setting"

    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    value: Mapped[str] = mapped_column(Text, default="")
