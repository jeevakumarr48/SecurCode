"""End-to-end API workflow: project → upload → background scan → triage → rescan → verification → export."""

import json

from app.v1.services.reports import validate_sarif

from .conftest import invite_and_join
from .helpers import create_upload_project, run_worker, upload_and_scan, zip_directory


def test_full_vulnerability_lifecycle(owner, make_client):
    developer = invite_and_join(owner, make_client, "dev@alpha.example.com", "developer")
    org = owner.org_id
    project = create_upload_project(owner)

    queued = upload_and_scan(owner, project["id"], zip_directory("demo-vulnerable-app"))
    assert queued["status"] == "queued"  # API returns immediately; the worker does the work
    assert run_worker() == ["completed"]
    scan = owner.get(f"/api/v1/organizations/{org}/scans/{queued['id']}").json()
    assert scan["status"] == "completed" and scan["files_scanned"] == 2
    assert scan["summary"]["total"] == 9 and scan["summary"]["new"] == 9
    assert scan["scanner_version"] and scan["ruleset_version"] and scan["rule_count"] > 40
    assert not scan["is_clean"]

    findings = owner.get(f"/api/v1/organizations/{org}/findings", params={"project_id": project["id"]}).json()
    assert findings["total"] == 9
    assert findings["items"][0]["severity"] == "critical"  # sorted by severity
    sql = next(f for f in findings["items"] if f["rule_id"] == "PYSEC007")
    detail = owner.get(f"/api/v1/organizations/{org}/findings/{sql['id']}").json()
    assert "SELECT * FROM users" in detail["snippet"]
    assert detail["guidance"]["cwe"] == "CWE-89" and detail["guidance"]["recommended_fix"]
    assert detail["events"][0]["kind"] == "system"

    # Developers only see projects they were added to; assignment adds them.
    assert developer.get(f"/api/v1/organizations/{org}/findings/{sql['id']}").status_code == 404
    assigned = owner.patch(f"/api/v1/organizations/{org}/findings/{sql['id']}",
                           json={"assignee_id": developer.user["id"], "status": "triaged"})
    assert assigned.status_code == 200, assigned.text
    notes = developer.get("/api/v1/notifications").json()
    assert any(n["kind"] == "finding_assigned" for n in notes["items"])

    # Developer may move their assigned finding to in_progress/fixed but not accept risk.
    denied = developer.patch(f"/api/v1/organizations/{org}/findings/{sql['id']}",
                             json={"status": "accepted_risk", "justification": "x" * 30})
    assert denied.status_code == 403  # valid transition, but not for a developer
    assert developer.patch(f"/api/v1/organizations/{org}/findings/{sql['id']}", json={"status": "in_progress"}).status_code == 200
    comment = developer.post(f"/api/v1/organizations/{org}/findings/{sql['id']}/comments", json={"body": "Switching to bound params."})
    assert comment.status_code == 201
    assert developer.patch(f"/api/v1/organizations/{org}/findings/{sql['id']}", json={"status": "fixed"}).status_code == 200
    # "resolved" is reserved for scan verification.
    assert owner.patch(f"/api/v1/organizations/{org}/findings/{sql['id']}", json={"status": "resolved"}).status_code == 409

    # Rescan with the fixed code: 7 findings verified fixed, 2 remain.
    second = upload_and_scan(owner, project["id"], zip_directory("demo-vulnerable-app-fixed"))
    assert run_worker() == ["completed"]
    rescanned = owner.get(f"/api/v1/organizations/{org}/scans/{second['id']}").json()
    assert rescanned["summary"]["resolved"] == 7 and rescanned["summary"]["new"] == 0 and rescanned["summary"]["total"] == 2
    verified = owner.get(f"/api/v1/organizations/{org}/findings/{sql['id']}").json()
    assert verified["status"] == "resolved" and verified["verification_status"] == "verified_fixed"
    assert verified["fixed_scan_id"] == second["id"]
    remaining = owner.get(f"/api/v1/organizations/{org}/findings",
                          params={"project_id": project["id"], "status": ["open", "triaged", "in_progress", "fixed", "reopened"]}).json()
    assert sorted(f["rule_id"] for f in remaining["items"]) == ["JSSEC010", "PYSEC012"]
    md5 = next(f for f in remaining["items"] if f["rule_id"] == "PYSEC012")
    assert md5["line"] == 33  # moved line, same fingerprint, same finding
    assert md5["first_scan_id"] == queued["id"]

    comparison = owner.get(f"/api/v1/organizations/{org}/scans/{queued['id']}/compare/{second['id']}").json()
    assert comparison["equivalent"] is True
    assert comparison["summary"]["resolved"] == 7 and comparison["summary"]["unchanged"] == 2 and comparison["summary"]["new"] == 0

    # Regression: vulnerable code comes back → finding reopens as a recurrence.
    third = upload_and_scan(owner, project["id"], zip_directory("demo-vulnerable-app"))
    run_worker()
    reopened = owner.get(f"/api/v1/organizations/{org}/findings/{sql['id']}").json()
    assert reopened["status"] == "reopened" and reopened["recurrence_count"] == 1
    assert owner.get(f"/api/v1/organizations/{org}/scans/{third['id']}").json()["summary"]["reopened"] == 7

    # Exports
    sarif = owner.get(f"/api/v1/organizations/{org}/exports/findings", params={"format": "sarif", "project_id": project["id"]})
    assert sarif.status_code == 200
    document = json.loads(sarif.text)
    assert validate_sarif(document) == []
    assert len(document["runs"][0]["results"]) == 9
    csv_export = owner.get(f"/api/v1/organizations/{org}/exports/findings", params={"format": "csv"})
    assert csv_export.text.splitlines()[0].startswith("id,project,rule_id")
    report = owner.get(f"/api/v1/organizations/{org}/reports/project", params={"project_id": project["id"]})
    assert report.status_code == 200 and "Limitations" in report.text and "Scanner version" in report.text
    assert "style-src 'unsafe-inline'" in report.headers["content-security-policy"]

    dashboard = owner.get(f"/api/v1/organizations/{org}/analytics/dashboard").json()
    assert dashboard["totals"]["active_findings"] == 9 and dashboard["totals"]["scans"] == 3
    assert dashboard["scan_health"]["success_rate"] == 1.0
    assert dashboard["posture"]["projects"][0]["score"] is not None


def test_scan_with_no_supported_files_is_not_clean(owner):
    from .helpers import zip_members

    project = create_upload_project(owner)
    scan = upload_and_scan(owner, project["id"], zip_members({"README.md": b"hello"}))
    run_worker()
    result = owner.get(f"/api/v1/organizations/{owner.org_id}/scans/{scan['id']}").json()
    assert result["status"] == "completed_with_warnings"
    assert result["is_clean"] is False
    assert any("not a clean result" in w["message"] for w in result["warnings"])


def test_partial_scan_does_not_auto_resolve(owner):
    from .helpers import zip_members

    project = create_upload_project(owner)
    upload_and_scan(owner, project["id"], zip_directory("demo-vulnerable-app"))
    run_worker()
    # Second archive contains a file that is skipped (oversized) → warnings → no auto-resolution.
    big = b"x = 1\n" * 400_000
    upload_and_scan(owner, project["id"], zip_members({"app/huge.py": big, "app/ok.py": b"value = 1\n"}))
    assert run_worker() == ["completed_with_warnings"]
    findings = owner.get(f"/api/v1/organizations/{owner.org_id}/findings", params={"project_id": project["id"]}).json()
    assert all(f["status"] == "open" for f in findings["items"])


def test_malicious_archive_fails_safely(owner):
    from .helpers import zip_members

    project = create_upload_project(owner)
    scan = upload_and_scan(owner, project["id"], zip_members({"../../evil.py": b"import os"}))
    assert run_worker() == ["failed"]
    result = owner.get(f"/api/v1/organizations/{owner.org_id}/scans/{scan['id']}").json()
    assert result["status"] == "failed" and "path-traversal" in result["error_message"]
    notes = owner.get("/api/v1/notifications").json()["items"]
    assert any(n["kind"] == "scan_failed" for n in notes)


def test_non_archive_upload_rejected(owner):
    project = create_upload_project(owner)
    response = owner.post(f"/api/v1/organizations/{owner.org_id}/projects/{project['id']}/scans/upload",
                          files={"file": ("x.zip", b"#!/bin/sh\necho hi", "application/zip")})
    assert response.status_code == 422


def test_cancel_queued_scan_and_idempotency(owner):
    project = create_upload_project(owner)
    owner.post(f"/api/v1/organizations/{owner.org_id}/projects/{project['id']}/archives",
               files={"file": ("a.zip", zip_directory("demo-vulnerable-app"), "application/zip")})
    url = f"/api/v1/organizations/{owner.org_id}/projects/{project['id']}/scans"
    first = owner.post(url, headers={"Idempotency-Key": "retry-key-123"}).json()
    again = owner.post(url, headers={"Idempotency-Key": "retry-key-123"}).json()
    assert first["id"] == again["id"]
    cancelled = owner.post(f"/api/v1/organizations/{owner.org_id}/scans/{first['id']}/cancel").json()
    assert cancelled["status"] == "cancelled"
    assert run_worker() == []
    assert owner.post(f"/api/v1/organizations/{owner.org_id}/scans/{first['id']}/cancel").status_code == 409


def test_risk_acceptance_requires_independent_review(owner, make_client):
    analyst = invite_and_join(owner, make_client, "analyst@alpha.example.com", "security_analyst")
    project = create_upload_project(owner)
    upload_and_scan(owner, project["id"], zip_directory("demo-vulnerable-app"))
    run_worker()
    finding = owner.get(f"/api/v1/organizations/{owner.org_id}/findings", params={"project_id": project["id"]}).json()["items"][-1]
    base = f"/api/v1/organizations/{owner.org_id}"
    # Analysts cannot set accepted_risk directly while the policy requires review.
    direct = analyst.patch(f"{base}/findings/{finding['id']}", json={"status": "accepted_risk", "justification": "y" * 25})
    assert direct.status_code == 403
    review = analyst.post(f"{base}/findings/{finding['id']}/reviews",
                          json={"kind": "accepted_risk", "justification": "Compensating WAF rule blocks this path until Q3."})
    assert review.status_code == 201
    assert analyst.post(f"{base}/reviews/{review.json()['id']}/decision", json={"approve": True}).status_code == 403
    pending = owner.get(f"{base}/reviews").json()["items"]
    assert len(pending) == 1
    decided = owner.post(f"{base}/reviews/{review.json()['id']}/decision", json={"approve": True, "note": "Approved for 90 days"})
    assert decided.status_code == 200 and decided.json()["expires_at"]
    assert owner.get(f"{base}/findings/{finding['id']}").json()["status"] == "accepted_risk"
    report = owner.get(f"{base}/reports/risk_acceptance")
    assert "Compensating WAF rule" in report.text


def test_bulk_assignment_and_filters(owner, make_client):
    dev = invite_and_join(owner, make_client, "bulk@alpha.example.com", "developer")
    project = create_upload_project(owner)
    upload_and_scan(owner, project["id"], zip_directory("demo-vulnerable-app"))
    run_worker()
    base = f"/api/v1/organizations/{owner.org_id}"
    highs = owner.get(f"{base}/findings", params={"severity": ["high"]}).json()["items"]
    result = owner.post(f"{base}/findings/bulk", json={"finding_ids": [f["id"] for f in highs], "assignee_id": dev.user["id"],
                                                       "add_labels": ["sprint-12"]}).json()
    assert len(result["updated"]) == len(highs) and not result["failed"]
    mine = dev.get(f"{base}/findings", params={"assignee": "me"}).json()
    assert mine["total"] == len(highs)
    labelled = owner.get(f"{base}/findings", params={"label": "sprint-12"}).json()
    assert labelled["total"] == len(highs)
    searched = owner.get(f"{base}/findings", params={"search": "server.py"}).json()
    assert searched["total"] == 7
