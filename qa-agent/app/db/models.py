"""
NEXUS QA Database Models

SQLAlchemy ORM models for all database entities.
Supports PostgreSQL (production) and SQLite (development).
"""

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum as SQLEnum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    JSON,
    func,
)
from sqlalchemy.dialects.postgresql import UUID, ARRAY
from sqlalchemy.orm import relationship
from sqlalchemy.ext.hybrid import hybrid_property
from enum import Enum

from .base import Base


# =============================================================================
# Enums
# =============================================================================


class ScanStatus(str, Enum):
    """Scan execution status."""
    PENDING = "pending"
    QUEUED = "queued"
    INITIALIZING = "initializing"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


class ScanType(str, Enum):
    """Type of security scan."""
    QUICK = "quick"
    DEEP = "deep"
    AUTONOMOUS = "autonomous"
    LIVE = "live"
    BULK = "bulk"


class Severity(str, Enum):
    """Finding severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class UserRole(str, Enum):
    """User roles for RBAC."""
    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"
    VIEWER = "viewer"


class PlanType(str, Enum):
    """Subscription plan types."""
    FREE = "free"
    STARTER = "starter"
    GROWTH = "growth"
    ENTERPRISE = "enterprise"


# =============================================================================
# Helper function for UUID
# =============================================================================


def generate_uuid():
    return str(uuid.uuid4())


# =============================================================================
# Models
# =============================================================================


class Tenant(Base):
    """Multi-tenant organization."""

    __tablename__ = "tenants"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(255), nullable=False)
    slug = Column(String(100), unique=True, nullable=False)
    plan = Column(String(50), default=PlanType.FREE.value)
    api_key_hash = Column(String(255), nullable=True)

    # Limits
    scan_limit_monthly = Column(Integer, default=10)
    scan_count_monthly = Column(Integer, default=0)
    last_reset_at = Column(DateTime, nullable=True)

    # Settings
    settings = Column(JSON, default=dict)

    # Billing
    stripe_customer_id = Column(String(255), nullable=True)
    stripe_subscription_id = Column(String(255), nullable=True)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    users = relationship("User", back_populates="tenant", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="tenant", cascade="all, delete-orphan")
    webhooks = relationship("Webhook", back_populates="tenant", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_tenants_slug", "slug"),
        Index("idx_tenants_plan", "plan"),
    )


class User(Base):
    """User account."""

    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False)
    email = Column(String(255), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=True)
    name = Column(String(255), nullable=True)
    role = Column(String(50), default=UserRole.MEMBER.value)

    # SSO
    sso_provider = Column(String(50), nullable=True)
    sso_id = Column(String(255), nullable=True)

    # Status
    is_active = Column(Boolean, default=True)
    email_verified = Column(Boolean, default=False)
    last_login_at = Column(DateTime, nullable=True)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    tenant = relationship("Tenant", back_populates="users")
    scans = relationship("Scan", back_populates="user")

    __table_args__ = (
        Index("idx_users_tenant", "tenant_id"),
        Index("idx_users_email", "email"),
    )


class Scan(Base):
    """Security scan record."""

    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=True)

    # Target
    url = Column(String(2048), nullable=False)
    scan_type = Column(String(50), default=ScanType.DEEP.value)

    # Status
    status = Column(String(50), default=ScanStatus.PENDING.value)
    progress = Column(Integer, default=0)
    phase = Column(String(50), nullable=True)
    phase_progress = Column(Integer, default=0)

    # Configuration
    config = Column(JSON, default=dict)
    frameworks = Column(JSON, default=list)  # ['owasp_top_10', 'vapt', ...]
    credentials_provided = Column(Boolean, default=False)

    # Checkpoint for resume (P0 feature)
    checkpoint = Column(JSON, nullable=True)
    checkpoint_phase = Column(String(50), nullable=True)
    checkpoint_at = Column(DateTime, nullable=True)

    # Timing
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Results summary
    overall_score = Column(Integer, nullable=True)
    findings_count = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)

    # Framework scores
    framework_scores = Column(JSON, default=dict)

    # Test plan (from AI)
    test_plan = Column(JSON, nullable=True)

    # Error info
    error_message = Column(Text, nullable=True)
    error_code = Column(String(20), nullable=True)

    # Celery task ID
    task_id = Column(String(255), nullable=True)

    # Relationships
    tenant = relationship("Tenant", back_populates="scans")
    user = relationship("User", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    events = relationship("ScanEvent", back_populates="scan", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="scan", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_scans_tenant", "tenant_id"),
        Index("idx_scans_status", "status"),
        Index("idx_scans_created", "created_at"),
        Index("idx_scans_url", "url"),
    )

    @hybrid_property
    def duration_seconds(self) -> Optional[int]:
        """Calculate scan duration in seconds."""
        if self.started_at and self.completed_at:
            return int((self.completed_at - self.started_at).total_seconds())
        return None

    @hybrid_property
    def is_running(self) -> bool:
        """Check if scan is currently running."""
        return self.status in [
            ScanStatus.INITIALIZING.value,
            ScanStatus.RUNNING.value,
        ]

    @hybrid_property
    def can_resume(self) -> bool:
        """Check if scan can be resumed from checkpoint."""
        return (
            self.checkpoint is not None and
            self.status in [
                ScanStatus.FAILED.value,
                ScanStatus.TIMEOUT.value,
                ScanStatus.PAUSED.value,
            ]
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "url": self.url,
            "scan_type": self.scan_type,
            "status": self.status,
            "progress": self.progress,
            "phase": self.phase,
            "overall_score": self.overall_score,
            "findings_count": self.findings_count,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "can_resume": self.can_resume,
        }


class Finding(Base):
    """Security finding/vulnerability."""

    __tablename__ = "findings"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False)

    # Check info
    check_id = Column(String(100), nullable=False)
    category = Column(String(100), nullable=False)

    # Finding details
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(20), nullable=False)
    evidence = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)

    # Location
    url = Column(String(2048), nullable=True)
    parameter = Column(String(255), nullable=True)
    method = Column(String(10), nullable=True)

    # Standards mapping
    cwe = Column(String(50), nullable=True)
    owasp = Column(String(100), nullable=True)
    cvss_score = Column(Float, nullable=True)
    cvss_vector = Column(String(100), nullable=True)

    # Status
    false_positive = Column(Boolean, default=False)
    resolved = Column(Boolean, default=False)
    resolved_at = Column(DateTime, nullable=True)
    resolved_by = Column(String(36), nullable=True)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    scan = relationship("Scan", back_populates="findings")

    __table_args__ = (
        Index("idx_findings_scan", "scan_id"),
        Index("idx_findings_severity", "severity"),
        Index("idx_findings_category", "category"),
        Index("idx_findings_check", "check_id"),
    )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "check_id": self.check_id,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "url": self.url,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "cvss_score": self.cvss_score,
            "false_positive": self.false_positive,
            "resolved": self.resolved,
        }


class ScanEvent(Base):
    """Real-time scan event for SSE streaming."""

    __tablename__ = "scan_events"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False)

    # Event info
    event_type = Column(String(100), nullable=False)
    message = Column(Text, nullable=True)
    data = Column(JSON, default=dict)

    # Screenshot (stored as URL, not base64)
    screenshot_url = Column(String(2048), nullable=True)

    # Phase tracking
    phase = Column(String(50), nullable=True)
    progress = Column(Integer, nullable=True)

    # Timestamp
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    scan = relationship("Scan", back_populates="events")

    __table_args__ = (
        Index("idx_events_scan", "scan_id"),
        Index("idx_events_type", "event_type"),
        Index("idx_events_created", "created_at"),
    )


class Report(Base):
    """Generated report."""

    __tablename__ = "reports"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False)

    # Report info
    format = Column(String(20), nullable=False)  # pdf, html, json, csv
    storage_url = Column(String(2048), nullable=True)
    storage_path = Column(String(500), nullable=True)
    file_size = Column(Integer, nullable=True)

    # Timestamps
    generated_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)

    # Relationships
    scan = relationship("Scan", back_populates="reports")

    __table_args__ = (
        Index("idx_reports_scan", "scan_id"),
        Index("idx_reports_format", "format"),
    )


class Webhook(Base):
    """Webhook configuration for notifications."""

    __tablename__ = "webhooks"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False)

    # Webhook config
    name = Column(String(255), nullable=False)
    url = Column(String(2048), nullable=False)
    secret_hash = Column(String(255), nullable=False)

    # Events to trigger
    events = Column(JSON, default=list)  # ['scan.completed', 'finding.critical']

    # Status
    is_active = Column(Boolean, default=True)
    last_triggered_at = Column(DateTime, nullable=True)
    last_status_code = Column(Integer, nullable=True)
    failure_count = Column(Integer, default=0)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    tenant = relationship("Tenant", back_populates="webhooks")

    __table_args__ = (
        Index("idx_webhooks_tenant", "tenant_id"),
        Index("idx_webhooks_active", "is_active"),
    )


class APICallLog(Base):
    """Captured API call during scan."""

    __tablename__ = "api_call_logs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False)

    # Request
    method = Column(String(10), nullable=False)
    url = Column(String(2048), nullable=False)
    path = Column(String(1024), nullable=True)
    host = Column(String(255), nullable=True)
    request_headers = Column(JSON, default=dict)
    request_body = Column(Text, nullable=True)
    content_type = Column(String(100), nullable=True)

    # Response
    status_code = Column(Integer, nullable=True)
    response_headers = Column(JSON, default=dict)
    response_body_sample = Column(Text, nullable=True)
    response_size = Column(Integer, nullable=True)
    response_time_ms = Column(Integer, nullable=True)

    # Analysis
    auth_required = Column(Boolean, default=False)
    sensitive_data = Column(Boolean, default=False)
    test_strategy = Column(JSON, default=list)

    # Timestamp
    captured_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        Index("idx_api_calls_scan", "scan_id"),
        Index("idx_api_calls_path", "path"),
    )


class Journey(Base):
    """Discovered user journey."""

    __tablename__ = "journeys"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False)

    # Journey info
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    journey_type = Column(String(50), nullable=True)  # login, signup, checkout, etc.

    # Steps
    start_url = Column(String(2048), nullable=True)
    steps = Column(JSON, default=list)
    status = Column(String(50), default="discovered")

    # Screenshots
    screenshots = Column(JSON, default=list)  # List of URLs

    # Timing
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        Index("idx_journeys_scan", "scan_id"),
        Index("idx_journeys_type", "journey_type"),
    )
