"""Fingerprint-based comparison of two scans of the same project."""

from __future__ import annotations

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Finding, Scan, ScanFinding

SUCCESS = {"completed", "completed_with_warnings"}


def _occurrences(db: Session, scan: Scan) -> dict[str, dict]:
    rows = db.execute(
        select(ScanFinding, Finding.title, Finding.status)
        .join(Finding, Finding.id == ScanFinding.finding_id)
        .where(ScanFinding.scan_id == scan.id)
    ).all()
    return {
        occ.fingerprint: {
            "finding_id": occ.finding_id, "rule_id": occ.rule_id, "title": title, "severity": occ.severity,
            "confidence": occ.confidence, "file_path": occ.file_path, "line": occ.line, "current_status": status,
        }
        for occ, title, status in rows
    }


def compare_scans(db: Session, base: Scan, head: Scan) -> dict:
    if base.project_id != head.project_id:
        raise HTTPException(status_code=422, detail="Only scans of the same project can be compared.")
    if base.status not in SUCCESS or head.status not in SUCCESS:
        raise HTTPException(status_code=409, detail="Both scans must have completed to be compared.")
    if base.created_at > head.created_at:
        base, head = head, base
    warnings = []
    if base.scope_key != head.scope_key:
        warnings.append(f"Different scan scopes ({base.scope_key} vs {head.scope_key}); results are not equivalent.")
    if base.scanner_version != head.scanner_version:
        warnings.append(f"Scanner versions differ ({base.scanner_version} vs {head.scanner_version}).")
    if base.ruleset_version != head.ruleset_version:
        warnings.append("Rule sets differ; some changes may come from rule changes rather than code changes.")
    if (base.config_json or {}).get("policy") != (head.config_json or {}).get("policy") or \
            (base.config_json or {}).get("disabled_rules") != (head.config_json or {}).get("disabled_rules"):
        warnings.append("Security policy filters differed between the scans.")
    for scan in (base, head):
        if scan.status == "completed_with_warnings":
            warnings.append(f"Scan {scan.id[:8]} completed with warnings; absent findings are not proof of a fix.")

    before, after = _occurrences(db, base), _occurrences(db, head)
    base_rules, head_rules = set(base.rule_ids or []), set(head.rule_ids or [])
    new = [after[fp] for fp in after.keys() - before.keys()]
    removed = [before[fp] for fp in before.keys() - after.keys()]
    unchanged, severity_changes, confidence_changes = [], [], []
    for fp in before.keys() & after.keys():
        old, cur = before[fp], after[fp]
        unchanged.append(cur)
        if old["severity"] != cur["severity"]:
            severity_changes.append({**cur, "from": old["severity"], "to": cur["severity"]})
        if old["confidence"] != cur["confidence"]:
            confidence_changes.append({**cur, "from": old["confidence"], "to": cur["confidence"]})
    resolved = [item for item in removed if item["rule_id"] in head_rules]
    out_of_scope = [item for item in removed if item["rule_id"] not in head_rules]
    recurring_ids = {
        row for row in db.execute(
            select(Finding.id).where(Finding.id.in_([i["finding_id"] for i in new] or ["-"]), Finding.recurrence_count > 0)
        ).scalars()
    }
    recurring = [item for item in new if item["finding_id"] in recurring_ids]
    key = lambda item: (item["file_path"], item["line"] or 0)  # noqa: E731
    return {
        "base_scan": {"id": base.id, "created_at": base.created_at.isoformat(), "status": base.status,
                      "scanner_version": base.scanner_version, "ruleset_version": base.ruleset_version, "scope": base.scope_key,
                      "commit_sha": base.commit_sha, "files_scanned": base.files_scanned},
        "head_scan": {"id": head.id, "created_at": head.created_at.isoformat(), "status": head.status,
                      "scanner_version": head.scanner_version, "ruleset_version": head.ruleset_version, "scope": head.scope_key,
                      "commit_sha": head.commit_sha, "files_scanned": head.files_scanned},
        "equivalent": not warnings,
        "warnings": warnings,
        "summary": {"new": len(new), "resolved": len(resolved), "recurring": len(recurring), "unchanged": len(unchanged),
                    "severity_changes": len(severity_changes), "confidence_changes": len(confidence_changes),
                    "no_longer_in_rule_scope": len(out_of_scope)},
        "rule_coverage": {"added": sorted(head_rules - base_rules), "removed": sorted(base_rules - head_rules)},
        "new": sorted(new, key=key),
        "resolved": sorted(resolved, key=key),
        "recurring": sorted(recurring, key=key),
        "unchanged": sorted(unchanged, key=key),
        "severity_changes": severity_changes,
        "confidence_changes": confidence_changes,
        "no_longer_in_rule_scope": sorted(out_of_scope, key=key),
    }
