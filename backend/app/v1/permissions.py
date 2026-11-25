"""Centralised organisation permission matrix.

The backend is the only enforcement point; the frontend receives the
effective permission list purely to hide controls the user cannot use.
"""

from __future__ import annotations

from enum import Enum


class P(str, Enum):
    ORG_VIEW = "org.view"
    ORG_UPDATE = "org.update"
    ORG_ARCHIVE = "org.archive"
    MEMBERS_VIEW = "members.view"
    MEMBERS_MANAGE = "members.manage"
    MEMBERS_MANAGE_PRIVILEGED = "members.manage_privileged"
    PROJECTS_VIEW_ALL = "projects.view_all"
    PROJECTS_CREATE = "projects.create"
    PROJECTS_MANAGE = "projects.manage"
    PROJECTS_DELETE = "projects.delete"
    SCANS_RUN = "scans.run"
    SCANS_CANCEL = "scans.cancel"
    FINDINGS_VIEW = "findings.view"
    FINDINGS_TRIAGE = "findings.triage"
    FINDINGS_REMEDIATE = "findings.remediate"
    FINDINGS_COMMENT = "findings.comment"
    FINDINGS_SEVERITY = "findings.severity"
    REVIEWS_REQUEST = "reviews.request"
    REVIEWS_APPROVE = "reviews.approve"
    POLICIES_VIEW = "policies.view"
    POLICIES_MANAGE = "policies.manage"
    INTEGRATIONS_VIEW = "integrations.view"
    INTEGRATIONS_MANAGE = "integrations.manage"
    REPORTS_VIEW = "reports.view"
    REPORTS_EXPORT = "reports.export"
    AUDIT_VIEW = "audit.view"
    SCHEDULES_MANAGE = "schedules.manage"


_VIEWER = {
    P.ORG_VIEW, P.MEMBERS_VIEW, P.FINDINGS_VIEW, P.REPORTS_VIEW, P.POLICIES_VIEW,
}
_DEVELOPER = _VIEWER | {P.FINDINGS_REMEDIATE, P.FINDINGS_COMMENT}
_ANALYST = _DEVELOPER | {
    P.PROJECTS_VIEW_ALL, P.SCANS_RUN, P.SCANS_CANCEL, P.FINDINGS_TRIAGE, P.REVIEWS_REQUEST,
    P.REPORTS_EXPORT, P.INTEGRATIONS_VIEW,
}
_SECURITY_ADMIN = _ANALYST | {
    P.FINDINGS_SEVERITY, P.REVIEWS_APPROVE, P.POLICIES_MANAGE, P.AUDIT_VIEW, P.SCHEDULES_MANAGE,
}
_ADMIN = _SECURITY_ADMIN | {
    P.ORG_UPDATE, P.MEMBERS_MANAGE, P.PROJECTS_CREATE, P.PROJECTS_MANAGE, P.PROJECTS_DELETE,
    P.INTEGRATIONS_MANAGE,
}
_OWNER = _ADMIN | {P.ORG_ARCHIVE, P.MEMBERS_MANAGE_PRIVILEGED}

ROLE_PERMISSIONS: dict[str, frozenset[P]] = {
    "owner": frozenset(_OWNER),
    "admin": frozenset(_ADMIN),
    "security_admin": frozenset(_SECURITY_ADMIN),
    "security_analyst": frozenset(_ANALYST),
    "developer": frozenset(_DEVELOPER),
    "viewer": frozenset(_VIEWER),
}

ROLE_RANK = {"viewer": 0, "developer": 1, "security_analyst": 2, "security_admin": 3, "admin": 4, "owner": 5}
PRIVILEGED_ROLES = {"owner", "admin"}

# Statuses a developer may set on findings assigned to them.
DEVELOPER_STATUSES = {"in_progress", "fixed"}


def has_permission(role: str | None, permission: P) -> bool:
    return bool(role) and permission in ROLE_PERMISSIONS.get(role, frozenset())


def permissions_for(role: str | None) -> list[str]:
    return sorted(p.value for p in ROLE_PERMISSIONS.get(role or "", frozenset()))


def can_assign_role(actor_role: str, target_role: str) -> bool:
    """Only owners grant or revoke owner/admin; admins manage lower roles."""
    if target_role in PRIVILEGED_ROLES:
        return has_permission(actor_role, P.MEMBERS_MANAGE_PRIVILEGED)
    return has_permission(actor_role, P.MEMBERS_MANAGE)


def permission_matrix() -> dict[str, list[str]]:
    return {role: permissions_for(role) for role in ROLE_PERMISSIONS}
