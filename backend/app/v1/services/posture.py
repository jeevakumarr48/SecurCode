"""Deterministic security posture score (0-100).

This is an internal prioritisation signal derived only from SecurCode
findings. It is NOT an industry certification and does not measure overall
security: it only reflects what the enabled rules detect in scanned code.

    risk = Σ  severity_weight × confidence_factor × age_factor × status_factor
    base = 100 × e^(−risk / 25)
    score = base × freshness_factor × coverage_factor

severity_weight   critical 10, high 5, medium 2, low 0.5, info 0
confidence_factor high 1.0, medium 0.7, low 0.4
age_factor        1 + min(age_days, 90)/90, plus 0.5 when past the due date
status_factor     in_progress 0.8, fixed (awaiting verification) 0.5, otherwise 1.0
freshness_factor  last successful scan ≤14 days 1.0, ≤30 days 0.85, older 0.7
coverage_factor   last scan completed with warnings (partial) 0.9, else 1.0
No successful scan → score is null ("not assessed").
Grades: A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, F < 40.
"""

from __future__ import annotations

import math

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import utcnow
from ..models import Finding, Project, Scan

SEVERITY_WEIGHT = {"critical": 10.0, "high": 5.0, "medium": 2.0, "low": 0.5, "info": 0.0}
CONFIDENCE_FACTOR = {"high": 1.0, "medium": 0.7, "low": 0.4}
STATUS_FACTOR = {"in_progress": 0.8, "fixed": 0.5}
ACTIVE = ("open", "triaged", "in_progress", "fixed", "reopened")
FORMULA_VERSION = "posture-v1"


def grade(score: float | None) -> str | None:
    if score is None:
        return None
    return "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"


def compute(findings, last_success: Scan | None, now=None) -> dict:
    now = now or utcnow()
    if last_success is None:
        return {"score": None, "grade": None, "risk_points": None, "assessed": False, "formula": FORMULA_VERSION,
                "reason": "No successful scan yet."}
    risk = 0.0
    for finding in findings:
        age_days = max((now - finding.first_detected_at).total_seconds() / 86400, 0)
        age = 1 + min(age_days, 90) / 90
        if finding.due_date and finding.due_date < now:
            age += 0.5
        risk += (SEVERITY_WEIGHT.get(finding.severity, 1.0) * CONFIDENCE_FACTOR.get(finding.confidence, 0.7)
                 * age * STATUS_FACTOR.get(finding.status, 1.0))
    base = 100 * math.exp(-risk / 25)
    scan_age = (now - (last_success.finished_at or last_success.created_at)).days
    freshness = 1.0 if scan_age <= 14 else 0.85 if scan_age <= 30 else 0.7
    coverage = 0.9 if last_success.status == "completed_with_warnings" else 1.0
    score = round(base * freshness * coverage, 1)
    return {
        "score": score, "grade": grade(score), "risk_points": round(risk, 2), "assessed": True,
        "freshness_factor": freshness, "coverage_factor": coverage, "last_scan_age_days": scan_age,
        "formula": FORMULA_VERSION,
    }


def project_posture(db: Session, project: Project) -> dict:
    last_success = db.execute(
        select(Scan).where(Scan.project_id == project.id, Scan.status.in_(["completed", "completed_with_warnings"]),
                           Scan.finished_at.is_not(None))
        .order_by(Scan.finished_at.desc())
        .limit(1)
    ).scalar_one_or_none()
    findings = db.execute(
        select(Finding).where(Finding.project_id == project.id, Finding.status.in_(ACTIVE))
    ).scalars().all()
    return compute(findings, last_success)
