"""Multi-tenant data model for the /api/v1 platform.

Every organisation-owned table carries ``org_id`` and every query against it
goes through :mod:`app.v1.tenancy` helpers that filter on that column.
Tables use the ``sc_`` prefix so they coexist with the legacy single-tenant
SQLite tables without collisions.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base, UTCDateTime, utcnow


def new_id() -> str:
    return uuid.uuid4().hex


ORG_ROLES = ("owner", "admin", "security_admin", "security_analyst", "developer", "viewer")
FINDING_STATUSES = (
    "open", "triaged", "in_progress", "fixed", "resolved", "accepted_risk", "false_positive", "reopened",
)
SCAN_STATUSES = ("queued", "running", "completed", "completed_with_warnings", "failed", "cancelled")
SEVERITIES = ("critical", "high", "medium", "low", "info")


def _in(values) -> str:
    return "(" + ",".join(f"'{value}'" for value in values) + ")"


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, onupdate=utcnow, nullable=False)


class User(TimestampMixin, Base):
    __tablename__ = "sc_users"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    email: Mapped[str] = mapped_column(String(254), unique=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_platform_admin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    email_verified_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(UTCDateTime())
    last_login_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    password_changed_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    mfa_secret_enc: Mapped[str | None] = mapped_column(Text)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    mfa_last_counter: Mapped[int | None] = mapped_column(Integer)
    legacy_user_id: Mapped[int | None] = mapped_column(Integer, unique=True)
    legacy_username: Mapped[str | None] = mapped_column(String(120), unique=True)

    memberships: Mapped[list[Membership]] = relationship(back_populates="user", cascade="all, delete-orphan")


class Organization(TimestampMixin, Base):
    __tablename__ = "sc_organizations"
    __table_args__ = (CheckConstraint(f"status IN {_in(('active', 'suspended', 'archived'))}", name="status"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    slug: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="active", nullable=False)
    settings_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_by_id: Mapped[str | None] = mapped_column(ForeignKey("sc_users.id", ondelete="SET NULL"))
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    memberships: Mapped[list[Membership]] = relationship(back_populates="organization", cascade="all, delete-orphan")


class Membership(TimestampMixin, Base):
    __tablename__ = "sc_memberships"
    __table_args__ = (
        UniqueConstraint("org_id", "user_id"),
        CheckConstraint(f"role IN {_in(ORG_ROLES)}", name="role"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("sc_organizations.id", ondelete="CASCADE"), index=True, nullable=False)
    user_id: Mapped[str] = mapped_column(ForeignKey("sc_users.id", ondelete="CASCADE"), index=True, nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False)

    organization: Mapped[Organization] = relationship(back_populates="memberships")
    user: Mapped[User] = relationship(back_populates="memberships")


class Invitation(TimestampMixin, Base):
    __tablename__ = "sc_invitations"
    __table_args__ = (CheckConstraint(f"role IN {_in(ORG_ROLES)}", name="role"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("sc_organizations.id", ondelete="CASCADE"), index=True, nullable=False)
    email: Mapped[str] = mapped_column(String(254), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    invited_by_id: Mapped[str | None] = mapped_column(ForeignKey("sc_users.id", ondelete="SET NULL"))
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    accepted_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    accepted_by_id: Mapped[str | None] = mapped_column(ForeignKey("sc_users.id", ondelete="SET NULL"))
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    send_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)


class UserSession(Base):
    __tablename__ = "sc_sessions"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(ForeignKey("sc_users.id", ondelete="CASCADE"), index=True, nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    csrf_token: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    ip_address: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(300))
    mfa_pending: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    active_org_id: Mapped[str | None] = mapped_column(ForeignKey("sc_organizations.id", ondelete="SET NULL"))


class OneTimeToken(Base):
    """Email verification and password reset tokens (stored hashed, single use)."""

    __tablename__ = "sc_one_time_tokens"
    __table_args__ = (CheckConstraint("purpose IN ('verify_email','reset_password')", name="purpose"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(ForeignKey("sc_users.id", ondelete="CASCADE"), index=True, nullable=False)
    purpose: Mapped[str] = mapped_column(String(32), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(UTCDateTime())


class RateEvent(Base):
    __tablename__ = "sc_rate_events"
    __table_args__ = (Index("ix_sc_rate_events_key_time", "key", "created_at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    key: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, nullable=False)


class Project(TimestampMixin, Base):
    __tablename__ = "sc_projects"
    __table_args__ = (
        UniqueConstraint("org_id", "slug"),
        CheckConstraint("status IN ('active','archived')", name="status"),
        CheckConstraint("source_type IN ('upload','github','fixture')", name="source_type"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("sc_organizations.id", ondelete="CASCADE"), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    slug: Mapped[str] = mapped_column(String(80), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    owner_id: Mapped[str | None] = mapped_column(ForeignKey("sc_users.id", ondelete="SET NULL"))
    status: Mapped[str] = mapped_column(String(20), default="active", nullable=False)
    source_type: Mapped[str] = mapped_column(String(20), default="upload", nullable=False)
    repository_provider: Mapped[str | None] = mapped_column(String(20))
    repository_full_name: Mapped[str | None] = mapped_column(String(200))
    repository_url: Mapped[str | None] = mapped_column(String(500))
    default_branch: Mapped[str] = mapped_column(String(200), default="main", nullable=False)
    integration_id: Mapped[str | None] = mapped_column(ForeignKey("sc_integrations.id", ondelete="SET NULL"))
    fixture_name: Mapped[str | None] = mapped_column(String(80))
    languages: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    last_scan_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    legacy_project_id: Mapped[int | None] = mapped_column(Integer)


class ProjectMember(TimestampMixin, Base):
    __tablename__ = "sc_project_members"
    __table_args__ = (
        UniqueConstraint("project_id", "user_id"),
        CheckConstraint("role IN ('maintainer','contributor','viewer')", name="role"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("sc_organizations.id", ondelete="CASCADE"), index=True, nullable=False)
    project_id: Mapped[str] = mapped_column(ForeignKey("sc_projects.id", ondelete="CASCADE"), index=True, nullable=False)
    user_id: Mapped[str] = mapped_column(ForeignKey("sc_users.id", ondelete="CASCADE"), index=True, nullable=False)
    role: Mapped[str] = mapped_column(String(20), default="contributor", nullable=False)


class SourceArchive(Base):
    """Uploaded source archives are kept in the database so that hosts with
    ephemeral filesystems do not lose them between the API and the worker."""

    __tablename__ = "sc_source_archives"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("sc_organizations.id", ondelete="CASCADE"), index=True, nullable=False)
    project_id: Mapped[str] = mapped_column(ForeignKey("sc_projects.id", ondelete="CASCADE"), index=True, nullable=False)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    archive_format: Mapped[str] = mapped_column(String(10), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    content: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    uploaded_by_id: Mapped[str | None] = mapped_column(ForeignKey("sc_users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, nullable=False)


class Scan(Base):
    __tablename__ = "sc_scans"
    __table_args__ = (
        CheckConstraint(f"status IN {_in(SCAN_STATUSES)}", name="status"),
        Index("ix_sc_scans_queue", "status", "created_at"),
        Index("ix_sc_scans_project_created", "project_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("sc_organizations.id", ondelete="CASCADE"), index=True, nullable=False)
    project_id: Mapped[str] = mapped_column(ForeignKey("sc_projects.id", ondelete="CASCADE"), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="queued", nullable=False)
    trigger: Mapped[str] = mapped_column(String(20), default="manual", nullable=False)
    source_type: Mapped[str] = mapped_column(String(20), nullable=False)
    archive_id: Mapped[str | None] = mapped_column(ForeignKey("sc_source_archives.id", ondelete="SET NULL"))
    branch: Mapped[str | None] = mapped_column(String(200))
    commit_sha: Mapped[str | None] = mapped_column(String(64))
    pull_request_number: Mapped[int | None] = mapped_column(Integer)
    base_scan_id: Mapped[str | None] = mapped_column(String(32))
    scope_key: Mapped[str] = mapped_column(String(250), nullable=False, default="default")
    requested_by_id: Mapped[str | None] = mapped_column(ForeignKey("sc_users.id", ondelete="SET NULL"))
    config_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    scanner_version: Mapped[str | None] = mapped_column(String(40))
    ruleset_version: Mapped[str | None] = mapped_column(String(40))
    rule_ids: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    progress: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    progress_message: Mapped[str] = mapped_column(String(200), default="Waiting for a worker", nullable=False)
    files_scanned: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    files_skipped: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    warnings: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    logs: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    summary: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    lease_owner: Mapped[str | None] = mapped_column(String(120))
    lease_expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    idempotency_key: Mapped[str | None] = mapped_column(String(120), unique=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    duration_ms: Mapped[int | None] = mapped_column(Integer)


class Finding(TimestampMixin, Base):
    """A deduplicated vulnerability tracked across scans of one project scope."""

    __tablename__ = "sc_findings"
    __table_args__ = (
        UniqueConstraint("project_id", "scope_key", "fingerprint"),
        CheckConstraint(f"status IN {_in(FINDING_STATUSES)}", name="status"),
        CheckConstraint(f"severity IN {_in(SEVERITIES)}", name="severity"),
        Index("ix_sc_findings_org_status", "org_id", "status"),
        Index("ix_sc_findings_assignee", "assignee_id"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("sc_organizations.id", ondelete="CASCADE"), index=True, nullable=False)
    project_id: Mapped[str] = mapped_column(ForeignKey("sc_projects.id", ondelete="CASCADE"), index=True, nullable=False)
    scope_key: Mapped[str] = mapped_column(String(250), nullable=False, default="default")
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    rule_id: Mapped[str] = mapped_column(String(40), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    severity: Mapped[str] = mapped_column(String(10), nullable=False)
    original_severity: Mapped[str] = mapped_column(String(10), nullable=False)
    confidence: Mapped[str] = mapped_column(String(10), nullable=False, default="medium")
    language: Mapped[str | None] = mapped_column(String(30))
    cwe: Mapped[str | None] = mapped_column(String(20))
    owasp: Mapped[str | None] = mapped_column(String(80))
    file_path: Mapped[str] = mapped_column(String(1000), nullable=False)
    line: Mapped[int | None] = mapped_column(Integer)
    snippet: Mapped[str | None] = mapped_column(Text)
    remediation: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20), default="open", nullable=False)
    verification_status: Mapped[str] = mapped_column(String(20), default="unverified", nullable=False)
    assignee_id: Mapped[str | None] = mapped_column(ForeignKey("sc_users.id", ondelete="SET NULL"))
    due_date: Mapped[datetime | None] = mapped_column(UTCDateTime())
    labels: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    remediation_notes: Mapped[str | None] = mapped_column(Text)
    first_detected_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, nullable=False)
    last_detected_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, nullable=False)
    first_scan_id: Mapped[str | None] = mapped_column(String(32))
    last_scan_id: Mapped[str | None] = mapped_column(String(32))
    fixed_scan_id: Mapped[str | None] = mapped_column(String(32))
    recurrence_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)


class ScanFinding(Base):
    """One occurrence of a finding in a specific scan (enables comparisons)."""

    __tablename__ = "sc_scan_findings"
    __table_args__ = (UniqueConstraint("scan_id", "finding_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    org_id: Mapped[str] = mapped_column(ForeignKey("sc_organizations.id", ondelete="CASCADE"), index=True, nullable=False)
    scan_id: Mapped[str] = mapped_column(ForeignKey("sc_scans.id", ondelete="CASCADE"), index=True, nullable=False)
    finding_id: Mapped[str] = mapped_column(ForeignKey("sc_findings.id", ondelete="CASCADE"), index=True, nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    rule_id: Mapped[str] = mapped_column(String(40), nullable=False)
    severity: Mapped[str] = mapped_column(String(10), nullable=False)
    confidence: Mapped[str] = mapped_column(String(10), nullable=False)
    file_path: Mapped[str] = mapped_column(String(1000), nullable=False)
    line: Mapped[int | None] = mapped_column(Integer)


class FindingEvent(Base):
    """Append-only activity: comments, status changes, assignment, etc."""

    __tablename__ = "sc_finding_events"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("sc_organizations.id", ondelete="CASCADE"), index=True, nullable=False)
    finding_id: Mapped[str] = mapped_column(ForeignKey("sc_findings.id", ondelete="CASCADE"), index=True, nullable=False)
    actor_id: Mapped[str | None] = mapped_column(ForeignKey("sc_users.id", ondelete="SET NULL"))
    kind: Mapped[str] = mapped_column(String(30), nullable=False)
    body: Mapped[str | None] = mapped_column(Text)
    from_value: Mapped[str | None] = mapped_column(String(200))
    to_value: Mapped[str | None] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, nullable=False)


class FindingReview(TimestampMixin, Base):
    """Risk-acceptance and false-positive requests that need reviewer approval."""

    __tablename__ = "sc_finding_reviews"
    __table_args__ = (
        CheckConstraint("kind IN ('accepted_risk','false_positive')", name="kind"),
        CheckConstraint("status IN ('pending','approved','rejected','expired')", name="status"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("sc_organizations.id", ondelete="CASCADE"), index=True, nullable=False)
    finding_id: Mapped[str] = mapped_column(ForeignKey("sc_findings.id", ondelete="CASCADE"), index=True, nullable=False)
    kind: Mapped[str] = mapped_column(String(20), nullable=False)
    justification: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="pending", nullable=False)
    requested_by_id: Mapped[str | None] = mapped_column(ForeignKey("sc_users.id", ondelete="SET NULL"))
    reviewer_id: Mapped[str | None] = mapped_column(ForeignKey("sc_users.id", ondelete="SET NULL"))
    reviewer_note: Mapped[str | None] = mapped_column(Text)
    reviewed_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    previous_status: Mapped[str] = mapped_column(String(20), nullable=False, default="open")


class AuditEvent(Base):
    """Hash-chained audit trail. No API exposes update or delete."""

    __tablename__ = "sc_audit_events"
    __table_args__ = (Index("ix_sc_audit_org_time", "org_id", "created_at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    org_id: Mapped[str | None] = mapped_column(String(32), index=True)
    project_id: Mapped[str | None] = mapped_column(String(32))
    actor_id: Mapped[str | None] = mapped_column(String(32))
    actor_email: Mapped[str | None] = mapped_column(String(254))
    action: Mapped[str] = mapped_column(String(80), nullable=False)
    resource_type: Mapped[str | None] = mapped_column(String(40))
    resource_id: Mapped[str | None] = mapped_column(String(64))
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(64))
    request_id: Mapped[str | None] = mapped_column(String(64))
    scope: Mapped[str] = mapped_column(String(10), default="org", nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, nullable=False)
    prev_hash: Mapped[str | None] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64), nullable=False)


class Notification(Base):
    __tablename__ = "sc_notifications"
    __table_args__ = (Index("ix_sc_notifications_user_read", "user_id", "read_at"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(ForeignKey("sc_users.id", ondelete="CASCADE"), nullable=False)
    org_id: Mapped[str | None] = mapped_column(ForeignKey("sc_organizations.id", ondelete="CASCADE"))
    kind: Mapped[str] = mapped_column(String(40), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    body: Mapped[str] = mapped_column(Text, default="", nullable=False)
    link: Mapped[str | None] = mapped_column(String(300))
    read_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, nullable=False)


class NotificationPreference(Base):
    __tablename__ = "sc_notification_preferences"
    __table_args__ = (UniqueConstraint("user_id", "kind"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(ForeignKey("sc_users.id", ondelete="CASCADE"), nullable=False)
    kind: Mapped[str] = mapped_column(String(40), nullable=False)
    in_app: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    email: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class SecurityPolicy(Base):
    __tablename__ = "sc_security_policies"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("sc_organizations.id", ondelete="CASCADE"), unique=True, nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    config: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    updated_by_id: Mapped[str | None] = mapped_column(ForeignKey("sc_users.id", ondelete="SET NULL"))
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, nullable=False)


class SecurityPolicyVersion(Base):
    __tablename__ = "sc_security_policy_versions"
    __table_args__ = (UniqueConstraint("org_id", "version"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("sc_organizations.id", ondelete="CASCADE"), index=True, nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    config: Mapped[dict] = mapped_column(JSON, nullable=False)
    changed_by_id: Mapped[str | None] = mapped_column(ForeignKey("sc_users.id", ondelete="SET NULL"))
    reason: Mapped[str] = mapped_column(Text, default="", nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, nullable=False)


class ScanSchedule(TimestampMixin, Base):
    __tablename__ = "sc_scan_schedules"
    __table_args__ = (CheckConstraint("frequency IN ('daily','weekly')", name="frequency"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("sc_organizations.id", ondelete="CASCADE"), index=True, nullable=False)
    project_id: Mapped[str] = mapped_column(ForeignKey("sc_projects.id", ondelete="CASCADE"), index=True, nullable=False)
    branch: Mapped[str | None] = mapped_column(String(200))
    frequency: Mapped[str] = mapped_column(String(10), nullable=False)
    hour: Mapped[int] = mapped_column(Integer, default=2, nullable=False)
    minute: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    weekday: Mapped[int | None] = mapped_column(Integer)
    timezone: Mapped[str] = mapped_column(String(64), default="UTC", nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    next_run_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), index=True)
    last_run_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    last_scan_id: Mapped[str | None] = mapped_column(String(32))
    last_error: Mapped[str | None] = mapped_column(Text)
    created_by_id: Mapped[str | None] = mapped_column(ForeignKey("sc_users.id", ondelete="SET NULL"))


class Integration(TimestampMixin, Base):
    __tablename__ = "sc_integrations"
    __table_args__ = (CheckConstraint("status IN ('active','error','revoked')", name="status"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("sc_organizations.id", ondelete="CASCADE"), index=True, nullable=False)
    provider: Mapped[str] = mapped_column(String(20), default="github", nullable=False)
    auth_type: Mapped[str] = mapped_column(String(20), default="token", nullable=False)
    account_login: Mapped[str | None] = mapped_column(String(120))
    credential_enc: Mapped[str | None] = mapped_column(Text)
    credential_hint: Mapped[str | None] = mapped_column(String(12))
    webhook_secret_enc: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20), default="active", nullable=False)
    last_error: Mapped[str | None] = mapped_column(Text)
    settings_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_by_id: Mapped[str | None] = mapped_column(ForeignKey("sc_users.id", ondelete="SET NULL"))


class WebhookDelivery(Base):
    __tablename__ = "sc_webhook_deliveries"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    provider: Mapped[str] = mapped_column(String(20), nullable=False)
    delivery_id: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    integration_id: Mapped[str | None] = mapped_column(String(32))
    event: Mapped[str] = mapped_column(String(60), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="received", nullable=False)
    detail: Mapped[str | None] = mapped_column(Text)
    received_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, nullable=False)


class ReportRecord(Base):
    __tablename__ = "sc_report_records"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("sc_organizations.id", ondelete="CASCADE"), index=True, nullable=False)
    project_id: Mapped[str | None] = mapped_column(String(32))
    kind: Mapped[str] = mapped_column(String(40), nullable=False)
    format: Mapped[str] = mapped_column(String(10), nullable=False)
    parameters: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_by_id: Mapped[str | None] = mapped_column(ForeignKey("sc_users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, nullable=False)


class WorkerHeartbeat(Base):
    __tablename__ = "sc_worker_heartbeats"

    worker_id: Mapped[str] = mapped_column(String(120), primary_key=True)
    hostname: Mapped[str] = mapped_column(String(120), nullable=False)
    version: Mapped[str] = mapped_column(String(40), nullable=False)
    started_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, nullable=False)
    active_jobs: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
