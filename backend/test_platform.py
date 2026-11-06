"""Regression coverage for the additive platform workflows."""

import asyncio
import json
import pytest
from fastapi import HTTPException
from pydantic import ValidationError
from urllib.parse import urlencode

import database
from app.api import platform_routes, routes
from app.main import app

_HTTP_TEST_TOKEN = None


@pytest.fixture
def platform_db(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "platform.db")
    monkeypatch.setattr(platform_routes, "DEMO_MODE", False)
    monkeypatch.setattr(routes, "DEMO_MODE", False)
    monkeypatch.setattr(platform_routes, "WORKSPACE_ROOT", tmp_path)
    monkeypatch.setattr(routes, "WORKSPACE_ROOT", tmp_path)
    database.initialize_database()
    yield tmp_path
    global _HTTP_TEST_TOKEN
    _HTTP_TEST_TOKEN = None


def _saved_scan(path="src", severity="HIGH"):
    return database.save_scan(path, {
        "status": "completed",
        "total_findings": 1,
        "findings": [{
            "severity": severity,
            "confidence": "HIGH",
            "test_id": "PYSEC003",
            "language": "Python",
            "filename": f"{path}/unsafe.py",
            "line_number": 3,
            "description": "Unsafe deserialization detected.",
        }],
    })


def _asgi_request(path, method="GET", body=None, params=None):
    async def dispatch():
        messages = []
        request_body = json.dumps(body).encode("utf-8") if body is not None else b""
        received = False

        async def receive():
            nonlocal received
            if received:
                return {"type": "http.disconnect"}
            received = True
            return {"type": "http.request", "body": request_body, "more_body": False}

        async def send(message):
            messages.append(message)

        query = urlencode(params or {}).encode("ascii")
        raw_path = path.encode("ascii")
        headers = [(b"host", b"test")]
        if _HTTP_TEST_TOKEN:
            headers.append((b"authorization", f"Bearer {_HTTP_TEST_TOKEN}".encode("ascii")))
        if body is not None:
            headers.append((b"content-type", b"application/json"))
        await asyncio.wait_for(app({
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": method,
            "scheme": "http",
            "path": path,
            "raw_path": raw_path,
            "query_string": query,
            "root_path": "",
            "headers": headers,
            "client": ("127.0.0.1", 10000),
            "server": ("test", 80),
        }, receive, send), timeout=30)
        start = next(message for message in messages if message["type"] == "http.response.start")
        response_body = b"".join(message.get("body", b"") for message in messages if message["type"] == "http.response.body")
        return start["status"], dict(start.get("headers", [])), response_body

    status, headers, response_body = asyncio.run(dispatch())
    try:
        parsed = json.loads(response_body) if response_body else None
    except json.JSONDecodeError:
        parsed = response_body.decode("utf-8")
    return status, headers, parsed


def test_finding_status_persists_history_and_audit_event(platform_db):
    scan_id = _saved_scan()

    updated = platform_routes.update_finding_status(
        scan_id,
        0,
        platform_routes.FindingStatusUpdate(status="In Progress", note="Owner is reviewing"),
    )

    assert updated["status"] == "In Progress"
    assert updated["status_history"][0]["from_status"] == "Open"
    assert updated["status_history"][0]["to_status"] == "In Progress"
    assert platform_routes.list_findings(status="In Progress", search="", limit=50, offset=0)["total"] == 1
    assert platform_routes.list_audit_events(limit=50, offset=0, action="finding.status_changed")["total"] == 1
    assert database.get_scan_history()[0]["findings"][0]["status"] == "In Progress"


def test_finding_assignment_validates_user_and_enforces_auth_and_role(platform_db, monkeypatch):
    global _HTTP_TEST_TOKEN
    monkeypatch.setenv("SECURCODE_BOOTSTRAP_TOKEN", "test-bootstrap-token-with-at-least-32-bytes")
    monkeypatch.setenv("SECURCODE_DEMO_MODE", "false")
    _HTTP_TEST_TOKEN = None
    scan_id = _saved_scan()

    assert _asgi_request(
        f"/findings/{scan_id}/0/assignee",
        "PATCH",
        {"assignee": "admin"},
    )[0] == 401

    bootstrap_status, _, bootstrap = _asgi_request("/auth/bootstrap", "POST", {
        "username": "assignment-owner",
        "password": "assignment-owner-password",
        "bootstrap_token": "test-bootstrap-token-with-at-least-32-bytes",
    })
    assert bootstrap_status == 201
    _HTTP_TEST_TOKEN = bootstrap["access_token"]
    admin_status, _, admin = _asgi_request("/auth/users", "POST", {
        "username": "admin",
        "password": "assignment-target-password",
        "role": "developer",
    })
    assert admin_status == 201
    viewer_status, _, _ = _asgi_request("/auth/users", "POST", {
        "username": "assignment-viewer",
        "password": "assignment-viewer-password",
        "role": "read_only",
    })
    assert viewer_status == 201
    viewer_login_status, _, viewer_session = _asgi_request("/auth/login", "POST", {
        "username": "assignment-viewer",
        "password": "assignment-viewer-password",
    })
    assert viewer_login_status == 200
    admin_token = _HTTP_TEST_TOKEN

    invalid_status, _, invalid = _asgi_request(
        f"/findings/{scan_id}/0/assignee",
        "PATCH",
        {"assignee": "no-such-user"},
    )
    assert invalid_status == 422
    assert invalid["detail"] == "Assignee must be an active SecurCode username."
    assert platform_routes.finding_detail(scan_id, 0)["assignee"] is None

    _HTTP_TEST_TOKEN = viewer_session["access_token"]
    assert _asgi_request(
        f"/findings/{scan_id}/0/assignee",
        "PATCH",
        {"assignee": "admin"},
    )[0] == 403

    _HTTP_TEST_TOKEN = admin_token
    assigned_status, _, assigned = _asgi_request(
        f"/findings/{scan_id}/0/assignee",
        "PATCH",
        {"assignee": "ADMIN"},
    )
    assert assigned_status == 200
    assert assigned["assignee"] == "admin"
    assert assigned["scan_id"] == scan_id
    assert assigned["finding_index"] == 0
    assert platform_routes.list_findings(search="", limit=50, offset=0)["findings"][0]["assignee"] == "admin"
    with database.get_connection() as connection:
        persisted = connection.execute(
            "SELECT assignee FROM finding_states WHERE scan_id = ? AND finding_index = 0",
            (scan_id,),
        ).fetchone()["assignee"]
        event = connection.execute(
            "SELECT actor, action FROM audit_events WHERE action = 'finding.assigned'"
        ).fetchone()
        connection.execute("UPDATE auth_users SET disabled = 1 WHERE id = ?", (admin["id"],))
    assert persisted == "admin"
    assert dict(event) == {"actor": "assignment-owner", "action": "finding.assigned"}

    disabled_status, _, disabled_error = _asgi_request(
        f"/findings/{scan_id}/0/assignee",
        "PATCH",
        {"assignee": "admin"},
    )
    assert disabled_status == 422
    assert disabled_error["detail"] == "Assignee must be an active SecurCode username."


def test_incident_workflow_links_findings_and_records_activity(platform_db):
    scan_id = _saved_scan(severity="CRITICAL")
    incident = platform_routes.create_incident(platform_routes.IncidentCreate(
        title="Suspicious unsafe parser path",
        finding_refs=[(scan_id, 0)],
    ))

    assert incident["severity"] == "Critical"
    assert len(incident["findings"]) == 1
    updated = platform_routes.update_incident(
        incident["id"],
        platform_routes.IncidentUpdate(status="Investigating", owner="Security engineering"),
    )

    assert updated["status"] == "Investigating"
    assert updated["activity"][-1]["action"] == "updated"
    assert platform_routes.list_audit_events(limit=50, offset=0, action="incident.created")["total"] == 1
    assert platform_routes.list_audit_events(limit=50, offset=0, action="incident.updated")["total"] == 1


def test_dashboard_uses_persisted_severity_and_documented_risk_score(platform_db):
    _saved_scan(severity="HIGH")

    summary = platform_routes.dashboard()

    assert summary["severity_counts"]["HIGH"] == 1
    assert summary["risk_score"] == 90
    assert "not breach likelihood" in summary["risk_score_method"]
    assert summary["most_affected_projects"][0]["project_path"] == "src"


def test_finding_identity_and_status_survive_rescans_and_reopen_if_detected(platform_db):
    first_scan = _saved_scan()
    initial = platform_routes.finding_detail(first_scan, 0)
    platform_routes.update_finding_status(
        first_scan,
        0,
        platform_routes.FindingStatusUpdate(status="Accepted Risk", note="Reviewed with application owner"),
    )
    second_scan = _saved_scan()
    second = platform_routes.finding_detail(second_scan, 0)

    assert second["finding_id"] == initial["finding_id"]
    assert second["status"] == "Accepted Risk"
    assert second["status_history"][-1]["to_status"] == "Accepted Risk"
    assert platform_routes.dashboard()["severity_counts"]["HIGH"] == 1

    platform_routes.update_finding_status(
        second_scan,
        0,
        platform_routes.FindingStatusUpdate(status="Resolved"),
    )
    third_scan = _saved_scan()
    assert platform_routes.finding_detail(third_scan, 0)["status"] == "Open"


def test_public_demo_scopes_findings_and_disables_lifecycle_changes(platform_db, monkeypatch):
    private_scan = _saved_scan("private-project")
    demo_scan = _saved_scan("backend/app/api/docs/security-demo", "MEDIUM")
    monkeypatch.setattr(platform_routes, "DEMO_MODE", True)

    findings = platform_routes.list_findings(search="", limit=50, offset=0)
    assert findings["total"] == 1
    assert findings["findings"][0]["scan_id"] == demo_scan
    with pytest.raises(HTTPException) as blocked:
        platform_routes.update_finding_status(
            private_scan,
            0,
            platform_routes.FindingStatusUpdate(status="Resolved"),
        )
    assert blocked.value.status_code == 403
    with pytest.raises(HTTPException) as hidden:
        platform_routes.finding_detail(private_scan, 0)
    assert hidden.value.status_code == 404
    assert platform_routes.list_incidents(limit=50, offset=0)["total"] == 0
    monkeypatch.setattr(routes, "DEMO_MODE", True)
    assert routes.scan_history()["total"] == 1
    assert routes.scan_history()["scans"][0]["project_path"] == "backend/app/api/docs/security-demo"
    assert routes.scan_statistics()["total_scans"] == 1


def test_api_responses_include_security_headers(platform_db):
    status_code, headers, _ = _asgi_request("/status")

    assert status_code == 200
    assert headers[b"x-content-type-options"] == b"nosniff"
    assert headers[b"x-frame-options"] == b"DENY"
    assert headers[b"referrer-policy"] == b"no-referrer"
    assert headers[b"permissions-policy"] == b"camera=(), microphone=(), geolocation=()"
    assert headers[b"content-security-policy"] == (
        b"default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
    )


def test_demo_cooldown_is_shared_through_sqlite(platform_db, monkeypatch):
    monkeypatch.setattr(routes, "DEMO_SCAN_COOLDOWN_SECONDS", 60)
    monkeypatch.setattr(routes, "_last_demo_scan_at", 0.0)
    routes._enforce_demo_scan_cooldown()

    # Reset the process-local timer to model a second API worker.
    monkeypatch.setattr(routes, "_last_demo_scan_at", 0.0)
    with pytest.raises(HTTPException) as limited:
        routes._enforce_demo_scan_cooldown()
    assert limited.value.status_code == 429


def test_dashboard_paths_are_redacted_before_api_response(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setattr(routes, "WORKSPACE_ROOT", workspace)
    private_path = str(tmp_path / "private-name" / "repository")
    result = routes.public_statistics({
        "latest_scan": {"project_path": private_path},
        "recent_scans": [{"project_path": private_path}],
        "most_affected_projects": [{"project_path": private_path}],
    })

    assert "private-name" not in str(result)
    assert result["recent_scans"][0]["project_path"] == "<outside-workspace>"


def test_project_registration_validates_workspace_path_and_records_event(platform_db):
    source_dir = platform_db / "checked-out"
    source_dir.mkdir()
    project = platform_routes.create_project(platform_routes.ProjectCreate(
        name="Checked out repository",
        project_path="checked-out",
        description="Local source tree",
    ))

    assert project["project_path"] == "checked-out"
    assert platform_routes.list_projects(limit=100, offset=0)["projects"][0]["name"] == "Checked out repository"
    assert platform_routes.list_audit_events(limit=50, offset=0, action="project.created")["total"] == 1


def test_project_repository_metadata_is_validated_and_editable(platform_db):
    source_dir = platform_db / "repo-metadata"
    source_dir.mkdir()
    with pytest.raises(ValidationError):
        platform_routes.ProjectCreate(name="Invalid URL", project_path="repo-metadata", repository_url="http://example.test/org/repo")
    project = platform_routes.create_project(platform_routes.ProjectCreate(
        name="Repository metadata", project_path="repo-metadata", owner="AppSec",
        repository_url="https://github.com/example/repo", default_branch="release",
    ))
    assert project["owner"] == "AppSec"
    assert project["repository_url"] == "https://github.com/example/repo"
    assert project["default_branch"] == "release"
    updated = platform_routes.update_project(project["id"], platform_routes.ProjectUpdate(default_branch="main"))
    assert updated["default_branch"] == "main"

    with pytest.raises(HTTPException) as traversal:
        platform_routes.create_project(platform_routes.ProjectCreate(name="Outside", project_path="../outside"))
    assert traversal.value.status_code == 400


def test_sarif_import_persists_attributed_findings_and_audit_event(platform_db):
    source_dir = platform_db / "repository"
    source_dir.mkdir()
    project = platform_routes.create_project(platform_routes.ProjectCreate(
        name="Imported findings", project_path="repository"))
    imported = platform_routes.import_sarif(platform_routes.SARIFImportRequest(
        project_id=project["id"],
        sarif={"version": "2.1.0", "runs": [{
            "tool": {"driver": {"name": "CodeQL", "rules": [{
                "id": "py/sql-injection",
                "properties": {"tags": ["CWE-89"], "security-severity": "8.0"},
            }]}},
            "results": [{
                "ruleId": "py/sql-injection", "level": "error",
                "message": {"text": "Untrusted SQL value."},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "src/db.py"},
                    "region": {"startLine": 12},
                }}],
            }],
        }]},
        branch="refs/pull/42/merge",
        commit_sha="A" * 40,
        pull_request_number=42,
        source_url="https://github.com/example/repository/actions/runs/123",
    ))

    assert imported["status"] == "completed"
    assert imported["scanner"] == "SARIF"
    assert imported["findings"][0]["scanner"] == "CodeQL"
    assert imported["findings"][0]["cwe"] == "CWE-89"
    assert imported["branch"] == "refs/pull/42/merge"
    assert imported["commit_sha"] == "a" * 40
    with database.get_connection() as connection:
        scan = connection.execute("SELECT branch_name, commit_sha, pull_request_number, source_url FROM scans WHERE id = ?", (imported["scan_id"],)).fetchone()
    assert dict(scan) == {
        "branch_name": "refs/pull/42/merge", "commit_sha": "a" * 40,
        "pull_request_number": 42, "source_url": "https://github.com/example/repository/actions/runs/123",
    }
    assert platform_routes.list_audit_events(limit=20, offset=0, action="integration.scan_imported")["total"] == 1


def test_external_scan_route_uses_project_target_and_persists_source(platform_db, monkeypatch):
    source_dir = platform_db / "external-project"
    source_dir.mkdir()
    project = platform_routes.create_project(platform_routes.ProjectCreate(
        name="External scan", project_path="external-project"))
    monkeypatch.setattr(platform_routes, "run_optional_scanner", lambda *args, **kwargs: [{
        "severity": "HIGH", "confidence": "HIGH", "test_id": "B608", "cwe": "CWE-89",
        "language": "Python", "filename": "src/db.py", "line_number": 5,
        "description": "Possible SQL injection", "scanner": "Bandit",
    }])

    result = platform_routes.run_external_scan("bandit", platform_routes.ExternalScanRequest(
        project_id=project["id"], timeout_seconds=10))

    assert result["status"] == "completed"
    assert result["scanner"] == "Bandit"
    assert result["findings"][0]["cwe"] == "CWE-89"
    assert database.get_scan_history()[0]["findings"][0]["scanner"] == "Bandit"


def test_vulnerability_dedup_assignment_comments_and_suppression_justification(platform_db):
    with database.get_connection() as connection:
        connection.execute(
            """INSERT INTO auth_users(username, password_salt, password_hash, role)
               VALUES ('security-user', '00', '00', 'developer')"""
        )
    first = _saved_scan()
    with pytest.raises(HTTPException) as missing_reason:
        platform_routes.update_finding_status(
            first, 0, platform_routes.FindingStatusUpdate(status="False Positive"))
    assert missing_reason.value.status_code == 400

    second = _saved_scan()
    listed = platform_routes.list_findings(search="", limit=50, offset=0)
    assert listed["total"] == 1
    assert listed["findings"][0]["scan_id"] == second

    assigned = platform_routes.update_finding_assignee(
        second, 0, platform_routes.FindingAssigneeUpdate(assignee="security-user"))
    commented = platform_routes.add_finding_comment(
        second, 0, platform_routes.FindingCommentCreate(comment="Patch prepared for review"))
    assert assigned["assignee"] == "security-user"
    assert commented["comments"][0]["comment"] == "Patch prepared for review"
    third = _saved_scan()
    assert platform_routes.finding_detail(third, 0)["comments"][0]["comment"] == "Patch prepared for review"
    audit_actions = {event["action"] for event in platform_routes.list_audit_events(limit=50, offset=0, action=None)["events"]}
    assert {"finding.assigned", "finding.commented"}.issubset(audit_actions)


def test_notifications_are_deduplicated_persisted_and_marked_read(platform_db):
    _saved_scan(severity="CRITICAL")
    notifications = platform_routes.list_notifications(unread_only=False, limit=50, offset=0)
    assert notifications["total"] == 2
    assert notifications["unread_count"] == 2
    critical = next(item for item in notifications["notifications"] if item["category"] == "critical_finding")

    updated = platform_routes.mark_notification_read(critical["id"])

    assert updated["read"] is True
    assert platform_routes.list_notifications(unread_only=True, limit=50, offset=0)["unread_count"] == 1
    with pytest.raises(HTTPException) as missing:
        platform_routes.mark_notification_read(99999)
    assert missing.value.status_code == 404


def test_public_demo_notifications_are_scoped_to_demo_scans(platform_db, monkeypatch):
    private_scan_id = _saved_scan(path="private-project", severity="CRITICAL")
    demo_scan_id = _saved_scan(
        path="backend/app/api/docs/security-demo",
        severity="CRITICAL",
    )
    monkeypatch.setattr(platform_routes, "DEMO_MODE", True)

    result = platform_routes.list_notifications(unread_only=False, limit=50, offset=0)

    assert result["total"] == 2
    assert result["unread_count"] == 2
    assert {item["event_key"] for item in result["notifications"]} == {
        f"scan:{demo_scan_id}",
        f"critical:{demo_scan_id}",
    }
    assert f"scan:{private_scan_id}" not in {
        item["event_key"] for item in result["notifications"]
    }


def test_project_membership_blocks_cross_project_access(platform_db, monkeypatch):
    global _HTTP_TEST_TOKEN
    monkeypatch.setenv("SECURCODE_BOOTSTRAP_TOKEN", "test-bootstrap-token-with-at-least-32-bytes")
    monkeypatch.setenv("SECURCODE_DEMO_MODE", "false")
    _HTTP_TEST_TOKEN = None
    bootstrap_status, _, bootstrap = _asgi_request("/auth/bootstrap", "POST", {
        "username": "scope-admin",
        "password": "scope-admin-password-long-enough",
        "bootstrap_token": "test-bootstrap-token-with-at-least-32-bytes",
    })
    assert bootstrap_status == 201
    _HTTP_TEST_TOKEN = bootstrap["access_token"]
    admin_token = bootstrap["access_token"]
    users = []
    for username in ("analyst-one", "analyst-two"):
        status_code, _, user = _asgi_request("/auth/users", "POST", {
            "username": username,
            "password": f"{username}-password-long-enough",
            "role": "security_analyst",
        })
        assert status_code == 201
        users.append(user)
    tokens = []
    for username in ("analyst-one", "analyst-two"):
        status_code, _, session = _asgi_request("/auth/login", "POST", {
            "username": username,
            "password": f"{username}-password-long-enough",
        })
        assert status_code == 200
        tokens.append(session["access_token"])

    project_ids = []
    scan_ids = []
    for name, token in zip(("alpha", "beta"), tokens):
        project_dir = platform_db / name
        project_dir.mkdir()
        (project_dir / "unsafe.py").write_text(
            "import pickle\npickle.loads(payload)\n", encoding="utf-8"
        )
        _HTTP_TEST_TOKEN = token
        create_status, _, project = _asgi_request("/projects", "POST", {
            "name": name,
            "project_path": name,
        })
        assert create_status == 201
        project_ids.append(project["id"])
        scan_status, _, _ = _asgi_request("/scan", "POST", {
            "project_path": name,
        })
        assert scan_status == 200
        with database.get_connection() as connection:
            scan = connection.execute(
                "SELECT id FROM scans WHERE project_id = ? ORDER BY id DESC LIMIT 1",
                (project["id"],),
            ).fetchone()
        scan_ids.append(scan["id"])

    _HTTP_TEST_TOKEN = tokens[0]
    own_project_status, _, _ = _asgi_request(f"/projects/{project_ids[0]}")
    assert own_project_status == 200
    own_findings_status, _, own_findings = _asgi_request(
        f"/projects/{project_ids[0]}/findings"
    )
    assert own_findings_status == 200
    assert own_findings["total"] == 1
    assert _asgi_request("/projects")[2]["total"] == 1

    _HTTP_TEST_TOKEN = tokens[1]
    assert _asgi_request(f"/projects/{project_ids[1]}")[0] == 200
    assert _asgi_request(f"/projects/{project_ids[0]}")[0] == 404
    assert _asgi_request(f"/projects/{project_ids[0]}/scan", "POST")[0] == 404
    assert _asgi_request(
        "/integrations/bandit/scan",
        "POST",
        {"project_id": project_ids[0], "timeout_seconds": 5},
    )[0] == 404
    assert _asgi_request(
        "/integrations/sarif/import",
        "POST",
        {
            "project_id": project_ids[0],
            "sarif": {"version": "2.1.0", "runs": []},
        },
    )[0] == 404
    assert _asgi_request(f"/findings/{scan_ids[0]}/0")[0] == 404
    assert _asgi_request(
        f"/findings/{scan_ids[0]}/0/status",
        "PATCH",
        {"status": "Resolved"},
    )[0] == 404
    assert _asgi_request(
        f"/projects/{project_ids[1]}/members",
        "POST",
        {"user_id": users[0]["id"]},
    )[0] == 403
    for path in (
        "/dashboard",
        "/history",
        "/stats",
        "/findings",
        "/incidents",
        "/audit",
        "/reports/summary",
        "/reports/findings.csv",
    ):
        assert _asgi_request(path)[0] == 403
    _HTTP_TEST_TOKEN = admin_token
    membership_status, _, _ = _asgi_request(
        f"/projects/{project_ids[0]}/members",
        "POST",
        {"user_id": users[1]["id"]},
    )
    assert membership_status == 201
    _HTTP_TEST_TOKEN = tokens[1]
    assert _asgi_request(f"/projects/{project_ids[0]}")[0] == 200
    assert _asgi_request("/projects")[2]["total"] == 2


def test_http_workflow_creates_project_scan_finding_incident_report_and_audit(platform_db, monkeypatch):
    global _HTTP_TEST_TOKEN
    monkeypatch.setenv("SECURCODE_BOOTSTRAP_TOKEN", "test-bootstrap-token-with-at-least-32-bytes")
    monkeypatch.setenv("SECURCODE_DEMO_MODE", "true")
    _HTTP_TEST_TOKEN = None
    assert _asgi_request("/auth/login", "POST", {"username": "hidden", "password": "not-a-real-password"})[0] == 404
    monkeypatch.setenv("SECURCODE_DEMO_MODE", "false")
    denied_status, _, _ = _asgi_request("/dashboard")
    assert denied_status == 401
    bootstrap_status, _, bootstrap = _asgi_request("/auth/bootstrap", "POST", {
        "username": "admin-user", "password": "a-very-long-test-password", "bootstrap_token": "test-bootstrap-token-with-at-least-32-bytes",
    })
    assert bootstrap_status == 201
    _HTTP_TEST_TOKEN = bootstrap["access_token"]
    user_status, _, viewer = _asgi_request("/auth/users", "POST", {
        "username": "viewer", "password": "viewer-password-long-enough", "role": "read_only",
    })
    assert user_status == 201
    login_status, _, viewer_session = _asgi_request("/auth/login", "POST", {
        "username": "viewer", "password": "viewer-password-long-enough",
    })
    assert login_status == 200
    admin_token = _HTTP_TEST_TOKEN
    _HTTP_TEST_TOKEN = viewer_session["access_token"]
    assert _asgi_request("/dashboard")[0] == 403
    assert _asgi_request("/auth/users")[0] == 403
    assert _asgi_request("/projects", "POST", {"name": "Forbidden", "project_path": "forbidden"})[0] == 403
    _HTTP_TEST_TOKEN = admin_token
    replacement_password = "replacement-password-that-must-not-be-audit-data"
    password_update_status, _, _ = _asgi_request(
        f"/auth/users/{viewer['id']}",
        "PATCH",
        {"password": replacement_password},
    )
    assert password_update_status == 200
    audit_status, _, audit_response = _asgi_request(
        "/audit", params={"action": "auth.user_updated"}
    )
    assert audit_status == 200
    with database.get_connection() as connection:
        credential_row = connection.execute(
            "SELECT password_hash, password_salt FROM auth_users WHERE id = ?",
            (viewer["id"],),
        ).fetchone()
        stored_audit = connection.execute(
            "SELECT metadata_json FROM audit_events WHERE action = 'auth.user_updated'"
        ).fetchone()["metadata_json"]
    serialized_audit = json.dumps(audit_response)
    assert replacement_password not in serialized_audit
    assert credential_row["password_hash"] not in serialized_audit
    assert credential_row["password_salt"] not in serialized_audit
    assert credential_row["password_hash"] not in stored_audit
    assert credential_row["password_salt"] not in stored_audit
    assert "password_hash" not in stored_audit
    assert "password_salt" not in stored_audit
    assert audit_response["events"][0]["metadata"] == {"changed_fields": ["password"]}

    source_dir = platform_db / "repo"
    source_dir.mkdir()
    (source_dir / "unsafe.py").write_text("import pickle\npickle.loads(payload)\n", encoding="utf-8")
    monkeypatch.setattr(platform_routes, "WORKSPACE_ROOT", platform_db)
    monkeypatch.setattr(routes, "WORKSPACE_ROOT", platform_db)

    project_status, _, project = _asgi_request("/projects", "POST", {"name": "Demo repository", "project_path": "repo"})
    assert project_status == 201
    scan_status, _, scan = _asgi_request("/scan", "POST", {"project_path": "repo"})
    assert scan_status == 200
    assert scan["total_findings"] == 1
    _, _, history = _asgi_request("/history")
    first_scan_id = history["scans"][0]["id"]
    _, _, project_detail = _asgi_request(f"/projects/{project['id']}")
    assert project_detail["scan_count"] == 1

    _, _, finding_list = _asgi_request("/findings", params={"severity": "HIGH"})
    assert finding_list["total"] == 1
    assert finding_list["findings"][0]["scan_id"] == first_scan_id
    first_finding_id = finding_list["findings"][0]["finding_id"]
    status_code, _, status = _asgi_request(f"/findings/{first_scan_id}/0/status", "PATCH", {"status": "Resolved", "note": "Patch merged"})
    assert status_code == 200
    assert status["status"] == "Resolved"

    rescan_status, _, rescan = _asgi_request(f"/projects/{project['id']}/scan", "POST")
    assert rescan_status == 200
    _, _, history = _asgi_request("/history")
    scan_id = history["scans"][0]["id"]
    _, _, comparison = _asgi_request(f"/scans/{scan_id}/comparison")
    assert comparison["compared_to_scan_id"] == first_scan_id
    assert comparison["unchanged_count"] == 1
    _, _, finding_detail = _asgi_request(f"/findings/{scan_id}/0")
    assert finding_detail["finding_id"] == first_finding_id
    assert finding_detail["status"] == "Open"

    incident_status, _, incident = _asgi_request("/incidents", "POST", {
        "title": "Review unsafe deserialization",
        "finding_refs": [[scan_id, 0]],
    })
    assert incident_status == 201
    incident_id = incident["id"]
    _, _, transition = _asgi_request(f"/incidents/{incident_id}", "PATCH", {"status": "Investigating"})
    assert transition["status"] == "Investigating"
    _, _, audit = _asgi_request("/audit", params={"action": "finding.status_changed"})
    assert audit["total"] == 1
    _, _, dashboard = _asgi_request("/dashboard")
    assert dashboard["total_scans"] == 2
    assert dashboard["severity_counts"]["HIGH"] == 1
    _, _, summary = _asgi_request("/reports/summary")
    assert summary["total_findings"] == 2
    csv_status, _, csv_body = _asgi_request("/reports/findings.csv")
    assert csv_status == 200
    assert "PYSEC003" in csv_body
    _HTTP_TEST_TOKEN = None
