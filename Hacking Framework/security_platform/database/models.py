"""
SQLAlchemy ORM models for all platform entities.

Design principles:
- UUIDs as primary keys (portable, cluster-safe)
- Enum columns for constrained value sets
- JSON columns for flexible metadata payloads
- Timestamps mixed in via TimestampMixin
- All relationships defined with explicit back_populates
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum as PyEnum
from typing import Dict, List, Optional

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database.database import Base


# ─── UUID helper ──────────────────────────────────────────────────────────────

def _uuid() -> str:
    return str(uuid.uuid4())


# ─── Enumerations ─────────────────────────────────────────────────────────────


class TargetType(str, PyEnum):
    DOMAIN = "domain"
    IP = "ip"
    NETWORK = "network"
    CLOUD = "cloud"
    URL = "url"


class TargetStatus(str, PyEnum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    ARCHIVED = "archived"


class ScanStatus(str, PyEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class SeverityLevel(str, PyEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "informational"


class ReportFormat(str, PyEnum):
    JSON = "json"
    HTML = "html"


# ─── Shared mixin ─────────────────────────────────────────────────────────────


class TimestampMixin:
    """Automatic created_at / updated_at timestamps for every entity."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


# ─── Models ───────────────────────────────────────────────────────────────────


class User(TimestampMixin, Base):
    """Platform operator / analyst account."""

    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    username: Mapped[str] = mapped_column(
        String(64), unique=True, nullable=False, index=True
    )
    email: Mapped[str] = mapped_column(
        String(255), unique=True, nullable=False, index=True
    )
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_superuser: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # Optional long-lived API key (stored hashed in production)
    api_key: Mapped[Optional[str]] = mapped_column(
        String(64), unique=True, nullable=True, index=True
    )

    # Relationships
    targets: Mapped[List["Target"]] = relationship(
        "Target", back_populates="owner", cascade="all, delete-orphan"
    )
    scans: Mapped[List["ScanResult"]] = relationship(
        "ScanResult", back_populates="initiated_by"
    )


class Target(TimestampMixin, Base):
    """A target asset under authorized security research."""

    __tablename__ = "targets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    value: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    target_type: Mapped[TargetType] = mapped_column(Enum(TargetType), nullable=False)
    status: Mapped[TargetStatus] = mapped_column(
        Enum(TargetStatus), default=TargetStatus.ACTIVE, nullable=False
    )
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    tags: Mapped[Optional[Dict]] = mapped_column(JSON, nullable=True)
    extra_metadata: Mapped[Optional[Dict]] = mapped_column(
        "metadata", JSON, nullable=True
    )
    owner_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id"), nullable=False
    )

    # Relationships
    owner: Mapped["User"] = relationship("User", back_populates="targets")
    assets: Mapped[List["Asset"]] = relationship(
        "Asset", back_populates="target", cascade="all, delete-orphan"
    )
    scan_results: Mapped[List["ScanResult"]] = relationship(
        "ScanResult", back_populates="target"
    )
    reports: Mapped[List["Report"]] = relationship(
        "Report", back_populates="target"
    )

    __table_args__ = (
        UniqueConstraint("value", "owner_id", name="uq_target_value_owner"),
    )


class Asset(TimestampMixin, Base):
    """A discovered asset (subdomain, IP, endpoint) belonging to a target."""

    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    target_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("targets.id"), nullable=False
    )
    value: Mapped[str] = mapped_column(String(512), nullable=False)
    asset_type: Mapped[str] = mapped_column(
        String(64), nullable=False
    )  # subdomain | ip | url | cloud_resource …
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    is_alive: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    extra_metadata: Mapped[Optional[Dict]] = mapped_column(
        "metadata", JSON, nullable=True
    )

    # Relationships
    target: Mapped["Target"] = relationship("Target", back_populates="assets")
    services: Mapped[List["Service"]] = relationship(
        "Service", back_populates="asset", cascade="all, delete-orphan"
    )


class Service(TimestampMixin, Base):
    """A network service detected on a discovered asset."""

    __tablename__ = "services"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    asset_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("assets.id"), nullable=False
    )
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(10), nullable=False, default="tcp")
    service_name: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    product: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    version: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    banner: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_open: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    extra_metadata: Mapped[Optional[Dict]] = mapped_column(
        "metadata", JSON, nullable=True
    )

    # Relationships
    asset: Mapped["Asset"] = relationship("Asset", back_populates="services")
    vulnerabilities: Mapped[List["Vulnerability"]] = relationship(
        "Vulnerability", back_populates="service"
    )


class Vulnerability(TimestampMixin, Base):
    """A vulnerability correlated with a detected service or asset."""

    __tablename__ = "vulnerabilities"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    service_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("services.id"), nullable=True
    )
    cve_id: Mapped[Optional[str]] = mapped_column(
        String(32), nullable=True, index=True
    )
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[SeverityLevel] = mapped_column(
        Enum(SeverityLevel), nullable=False
    )
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    references: Mapped[Optional[Dict]] = mapped_column(JSON, nullable=True)
    affected_software: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True
    )
    affected_version: Mapped[Optional[str]] = mapped_column(
        String(128), nullable=True
    )

    # Relationships
    service: Mapped[Optional["Service"]] = relationship(
        "Service", back_populates="vulnerabilities"
    )


class ScanResult(TimestampMixin, Base):
    """Tracks a complete scan execution including status and raw results."""

    __tablename__ = "scan_results"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    target_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("targets.id"), nullable=False
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id"), nullable=False
    )
    scan_type: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus), default=ScanStatus.PENDING, nullable=False
    )
    celery_task_id: Mapped[Optional[str]] = mapped_column(
        String(128), nullable=True, unique=True
    )
    started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    results: Mapped[Optional[Dict]] = mapped_column(JSON, nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    risk_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    modules_used: Mapped[Optional[Dict]] = mapped_column(JSON, nullable=True)

    # Relationships
    target: Mapped["Target"] = relationship("Target", back_populates="scan_results")
    initiated_by: Mapped["User"] = relationship("User", back_populates="scans")
    reports: Mapped[List["Report"]] = relationship(
        "Report", back_populates="scan_result"
    )


class Report(TimestampMixin, Base):
    """A generated security report attached to a target and optional scan."""

    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    target_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("targets.id"), nullable=False
    )
    scan_result_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("scan_results.id"), nullable=True
    )
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    format: Mapped[ReportFormat] = mapped_column(
        Enum(ReportFormat), nullable=False, default=ReportFormat.JSON
    )
    content: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    file_path: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    risk_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    summary: Mapped[Optional[Dict]] = mapped_column(JSON, nullable=True)

    # Relationships
    target: Mapped["Target"] = relationship("Target", back_populates="reports")
    scan_result: Mapped[Optional["ScanResult"]] = relationship(
        "ScanResult", back_populates="reports"
    )
