"""Organisation security policy defaults, validation and versioning."""

from __future__ import annotations

import fnmatch

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import utcnow
from ..models import SEVERITIES, SecurityPolicy, SecurityPolicyVersion

DEFAULT_POLICY = {
    "disabled_rules": {},              # rule_id -> justification
    "minimum_severity": "low",         # findings below are not recorded
    "minimum_confidence": "low",
    "excluded_paths": ["tests/fixtures/**", "**/__snapshots__/**"],
    "max_file_bytes": 2_000_000,
    "max_archive_bytes": 25_000_000,
    "max_scan_seconds": 300,
    "pr_fail_severity": None,          # None = never block; else e.g. "high"
    "accepted_risk_max_days": 90,
    "false_positive_requires_review": True,
    "accepted_risk_requires_review": True,
    "default_due_days": {"critical": 7, "high": 30, "medium": 90, "low": 180},
}
CONFIDENCE_LEVELS = ("low", "medium", "high")
SEVERITY_ORDER = {name: index for index, name in enumerate(reversed(SEVERITIES))}  # info=0 … critical=4


def _validate(config: dict) -> dict:
    merged = {**DEFAULT_POLICY, **config}
    unknown = set(config) - set(DEFAULT_POLICY)
    if unknown:
        raise HTTPException(status_code=422, detail=f"Unknown policy keys: {', '.join(sorted(unknown))}")
    if merged["minimum_severity"] not in SEVERITIES:
        raise HTTPException(status_code=422, detail="minimum_severity is invalid.")
    if merged["minimum_confidence"] not in CONFIDENCE_LEVELS:
        raise HTTPException(status_code=422, detail="minimum_confidence is invalid.")
    if merged["pr_fail_severity"] is not None and merged["pr_fail_severity"] not in SEVERITIES:
        raise HTTPException(status_code=422, detail="pr_fail_severity is invalid.")
    disabled = merged["disabled_rules"]
    if not isinstance(disabled, dict) or any(
        not isinstance(k, str) or not isinstance(v, str) or len(v.strip()) < 10 for k, v in disabled.items()
    ):
        raise HTTPException(status_code=422, detail="Each disabled rule needs a justification of at least 10 characters.")
    paths = merged["excluded_paths"]
    if not isinstance(paths, list) or len(paths) > 100 or any(not isinstance(p, str) or len(p) > 200 or ".." in p for p in paths):
        raise HTTPException(status_code=422, detail="excluded_paths must be up to 100 glob patterns without '..'.")
    for key, low, high in (
        ("max_file_bytes", 1024, 20_000_000),
        ("max_archive_bytes", 1024, 200_000_000),
        ("max_scan_seconds", 10, 3600),
        ("accepted_risk_max_days", 1, 730),
    ):
        value = merged[key]
        if not isinstance(value, int) or not low <= value <= high:
            raise HTTPException(status_code=422, detail=f"{key} must be an integer between {low} and {high}.")
    due = merged["default_due_days"]
    if not isinstance(due, dict) or any(k not in SEVERITIES or not isinstance(v, int) or not 1 <= v <= 730 for k, v in due.items()):
        raise HTTPException(status_code=422, detail="default_due_days must map severities to 1-730 days.")
    for flag in ("false_positive_requires_review", "accepted_risk_requires_review"):
        if not isinstance(merged[flag], bool):
            raise HTTPException(status_code=422, detail=f"{flag} must be true or false.")
    return merged


def ensure_policy(db: Session, org_id: str, actor_id: str | None = None) -> SecurityPolicy:
    policy = db.execute(select(SecurityPolicy).where(SecurityPolicy.org_id == org_id)).scalar_one_or_none()
    if policy is None:
        policy = SecurityPolicy(org_id=org_id, version=1, config=dict(DEFAULT_POLICY), updated_by_id=actor_id)
        db.add(policy)
        db.add(SecurityPolicyVersion(org_id=org_id, version=1, config=dict(DEFAULT_POLICY),
                                     changed_by_id=actor_id, reason="Initial default policy"))
        db.flush()
    return policy


def update_policy(db: Session, org_id: str, changes: dict, actor_id: str, reason: str) -> SecurityPolicy:
    policy = ensure_policy(db, org_id, actor_id)
    config = _validate({**policy.config, **changes})
    policy.config = config
    policy.version += 1
    policy.updated_by_id = actor_id
    policy.updated_at = utcnow()
    db.add(SecurityPolicyVersion(org_id=org_id, version=policy.version, config=config, changed_by_id=actor_id, reason=reason))
    db.flush()
    return policy


def effective_policy(db: Session, org_id: str) -> dict:
    return {**DEFAULT_POLICY, **ensure_policy(db, org_id).config}


def path_excluded(path: str, patterns: list[str]) -> bool:
    normalised = path.replace("\\", "/").lstrip("./")
    return any(fnmatch.fnmatch(normalised, pattern) or fnmatch.fnmatch("/" + normalised, pattern) for pattern in patterns)


def severity_at_least(severity: str, minimum: str) -> bool:
    return SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER.get(minimum, 0)


def confidence_at_least(confidence: str, minimum: str) -> bool:
    order = {name: i for i, name in enumerate(CONFIDENCE_LEVELS)}
    return order.get(confidence, 0) >= order.get(minimum, 0)
