"""GitHub integration (mocked GitHub API), webhooks, schedules and notifications."""

import hashlib
import hmac
import io
import json
import tarfile
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import httpx
import pytest

from app.v1.services import github as gh
from app.v1.services.schedule import next_run

from .helpers import FIXTURES, run_worker

TOKEN = "ghp_" + "T" * 36
SHA = "a" * 40


def _tarball() -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for path in (FIXTURES / "demo-vulnerable-app").rglob("*"):
            if path.is_file():
                archive.add(path, arcname=f"octo-shop-{SHA[:7]}/" + path.relative_to(FIXTURES / "demo-vulnerable-app").as_posix())
    return buffer.getvalue()


class FakeGitHub:
    def __init__(self):
        self.requests = []
        self.posted = []
        self.revoked = False

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        host, path = request.url.host, request.url.path
        if host == "codeload.github.com":
            assert "authorization" not in request.headers  # token never forwarded to the archive host
            return httpx.Response(200, content=_tarball())
        assert host == "api.github.com"
        if request.headers.get("authorization") != f"Bearer {TOKEN}" or self.revoked:
            return httpx.Response(401, json={"message": "Bad credentials"})
        if path == "/user":
            return httpx.Response(200, json={"login": "octocat", "type": "User"}, headers={"x-oauth-scopes": "repo"})
        if path == "/user/repos":
            return httpx.Response(200, json=[{"full_name": "octo/shop", "private": True, "default_branch": "main"}])
        if path == "/repos/octo/shop/branches":
            return httpx.Response(200, json=[{"name": "main", "commit": {"sha": SHA}}, {"name": "feature", "commit": {"sha": "b" * 40}}])
        if path.startswith("/repos/octo/shop/commits/"):
            return httpx.Response(200, text=SHA)
        if path == f"/repos/octo/shop/tarball/{SHA}":
            return httpx.Response(302, headers={"location": f"https://codeload.github.com/octo/shop/legacy.tar.gz/{SHA}?token=signed"})
        if request.method == "POST":
            self.posted.append((path, json.loads(request.content)))
            return httpx.Response(201, json={})
        return httpx.Response(404, json={})


@pytest.fixture
def fake_github():
    fake = FakeGitHub()
    gh.set_transport(httpx.MockTransport(fake))
    yield fake
    gh.set_transport(None)


def _connect(owner):
    response = owner.post(f"/api/v1/organizations/{owner.org_id}/integrations/github", json={"token": TOKEN, "auto_scan_push": True})
    assert response.status_code == 201, response.text
    return response.json()


def _signed(secret, payload):
    body = json.dumps(payload).encode()
    return body, "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def test_github_connect_scan_branch_and_secrets_never_exposed(owner, fake_github):
    integration = _connect(owner)
    assert integration["account_login"] == "octocat" and integration["credential_hint"] == f"…{TOKEN[-4:]}"
    assert TOKEN not in json.dumps(integration)
    listed = owner.get(f"/api/v1/organizations/{owner.org_id}/integrations").json()
    assert TOKEN not in json.dumps(listed) and "webhook_secret" not in listed["items"][0]
    repos = owner.get(f"/api/v1/organizations/{owner.org_id}/integrations/{integration['id']}/repositories").json()
    assert repos["items"][0]["full_name"] == "octo/shop"
    branches = owner.get(f"/api/v1/organizations/{owner.org_id}/integrations/{integration['id']}/repositories/octo/shop/branches").json()
    assert [b["name"] for b in branches["items"]] == ["main", "feature"]
    project = owner.post(f"/api/v1/organizations/{owner.org_id}/projects", json={
        "name": "Shop", "source_type": "github", "repository_full_name": "octo/shop", "integration_id": integration["id"]}).json()
    scan = owner.post(f"/api/v1/organizations/{owner.org_id}/projects/{project['id']}/scans", json={"branch": "main"}).json()
    assert scan["scope_key"] == "branch:main"
    assert run_worker() == ["completed"]
    done = owner.get(f"/api/v1/organizations/{owner.org_id}/scans/{scan['id']}").json()
    assert done["commit_sha"] == SHA and done["summary"]["total"] == 9


def test_invalid_token_rejected_and_disconnect_revokes(owner, fake_github):
    bad = owner.post(f"/api/v1/organizations/{owner.org_id}/integrations/github", json={"token": "ghp_" + "X" * 36})
    assert bad.status_code == 409
    integration = _connect(owner)
    removed = owner.delete(f"/api/v1/organizations/{owner.org_id}/integrations/{integration['id']}").json()
    assert removed["status"] == "revoked"
    assert owner.get(f"/api/v1/organizations/{owner.org_id}/integrations/{integration['id']}/repositories").status_code == 409


def test_expired_credential_marks_integration_error(owner, fake_github):
    integration = _connect(owner)
    fake_github.revoked = True
    response = owner.get(f"/api/v1/organizations/{owner.org_id}/integrations/{integration['id']}/repositories")
    assert response.status_code == 409
    status = owner.get(f"/api/v1/organizations/{owner.org_id}/integrations").json()["items"][0]
    assert status["status"] == "error" and "expired or revoked" in status["last_error"]


def test_webhook_signature_replay_and_pull_request_summary(owner, fake_github, make_client):
    integration = _connect(owner)
    secret = integration["webhook_secret"]
    owner.post(f"/api/v1/organizations/{owner.org_id}/projects", json={
        "name": "Shop", "source_type": "github", "repository_full_name": "octo/shop", "integration_id": integration["id"]})
    url = f"/api/v1/webhooks/github/{integration['id']}"
    anon = make_client().http
    payload = {"action": "opened", "number": 7, "repository": {"full_name": "octo/shop"},
               "pull_request": {"number": 7, "head": {"sha": SHA, "ref": "feature", "repo": {"full_name": "octo/shop"}}}}
    body, signature = _signed(secret, payload)
    assert anon.post(url, content=body, headers={"X-GitHub-Event": "pull_request", "X-GitHub-Delivery": "delivery-0001",
                                                 "X-Hub-Signature-256": "sha256=" + "0" * 64}).status_code == 401
    assert anon.post(f"/api/v1/webhooks/github/{'f' * 32}", content=body, headers={
        "X-GitHub-Event": "pull_request", "X-GitHub-Delivery": "delivery-0001", "X-Hub-Signature-256": signature}).status_code == 401
    first = anon.post(url, content=body, headers={"X-GitHub-Event": "pull_request", "X-GitHub-Delivery": "delivery-0001",
                                                  "X-Hub-Signature-256": signature})
    assert first.status_code == 202 and first.json()["status"] == "queued"
    replay = anon.post(url, content=body, headers={"X-GitHub-Event": "pull_request", "X-GitHub-Delivery": "delivery-0001",
                                                   "X-Hub-Signature-256": signature})
    assert replay.json()["status"] == "duplicate"
    assert run_worker() == ["completed"]
    statuses = [p for p in fake_github.posted if "/statuses/" in p[0]]
    comments = [p for p in fake_github.posted if "/comments" in p[0]]
    # No blocking policy configured → informational success, only detected findings reported.
    assert statuses[0][1]["state"] == "success" and statuses[0][1]["context"] == "securcode/sast"
    assert "New findings: 9" in comments[0][1]["body"] and "informational only" in comments[0][1]["body"]


def test_pr_threshold_policy_fails_status(owner, fake_github, make_client):
    owner.put(f"/api/v1/organizations/{owner.org_id}/policy", json={"changes": {"pr_fail_severity": "high"}, "reason": "Block high in PRs"})
    integration = _connect(owner)
    owner.post(f"/api/v1/organizations/{owner.org_id}/projects", json={
        "name": "Shop", "source_type": "github", "repository_full_name": "octo/shop", "integration_id": integration["id"]})
    payload = {"action": "synchronize", "number": 9, "repository": {"full_name": "octo/shop"},
               "pull_request": {"number": 9, "head": {"sha": SHA, "ref": "feature"}}}
    body, signature = _signed(integration["webhook_secret"], payload)
    make_client().http.post(f"/api/v1/webhooks/github/{integration['id']}", content=body, headers={
        "X-GitHub-Event": "pull_request", "X-GitHub-Delivery": "delivery-0009", "X-Hub-Signature-256": signature})
    run_worker()
    status = next(p for p in fake_github.posted if "/statuses/" in p[0])[1]
    assert status["state"] == "failure" and "at or above high" in status["description"]


def test_schedule_next_run_is_timezone_aware_and_runs_once(owner):
    schedule = SimpleNamespace(frequency="daily", hour=2, minute=30, weekday=None, timezone="Asia/Kolkata")
    after = datetime(2026, 11, 25, 0, 0, tzinfo=timezone.utc)  # 05:30 IST
    assert next_run(schedule, after) == datetime(2026, 11, 25, 21, 0, tzinfo=timezone.utc)  # 02:30 IST next day
    weekly = SimpleNamespace(frequency="weekly", hour=9, minute=0, weekday=0, timezone="America/New_York")
    # 2026-03-08 is the US DST change; next Monday 09:00 EDT = 13:00 UTC.
    assert next_run(weekly, datetime(2026, 3, 7, 12, 0, tzinfo=timezone.utc)) == datetime(2026, 3, 9, 13, 0, tzinfo=timezone.utc)

    from sqlalchemy import update

    from app.v1 import db as v1_db
    from app.v1.models import ScanSchedule
    from app.v1.worker import run_due_schedules

    project = owner.post(f"/api/v1/organizations/{owner.org_id}/projects",
                         json={"name": "Fixture", "source_type": "fixture", "fixture_name": "demo-vulnerable-app"}).json()
    created = owner.post(f"/api/v1/organizations/{owner.org_id}/schedules",
                         json={"project_id": project["id"], "frequency": "daily", "hour": 3, "timezone": "Asia/Kolkata"}).json()
    assert created["enabled"] is False and created["next_run_at"] is None  # disabled until explicitly enabled
    enabled = owner.patch(f"/api/v1/organizations/{owner.org_id}/schedules/{created['id']}", json={"enabled": True}).json()
    assert enabled["next_run_at"]
    with v1_db.SessionLocal() as db:
        db.execute(update(ScanSchedule).values(next_run_at=v1_db.utcnow() - timedelta(minutes=1)))
        db.commit()
    assert run_due_schedules() == 1
    assert run_due_schedules() == 0  # no duplicate execution
    assert run_worker() == ["completed"]
    history = owner.get(f"/api/v1/organizations/{owner.org_id}/schedules").json()["items"][0]["history"]
    assert len(history) == 1 and history[0]["status"] == "completed"


def test_notifications_read_state_and_preferences(owner):
    project = owner.post(f"/api/v1/organizations/{owner.org_id}/projects",
                         json={"name": "Fixture", "source_type": "fixture", "fixture_name": "demo-vulnerable-app"}).json()
    owner.post(f"/api/v1/organizations/{owner.org_id}/projects/{project['id']}/scans")
    run_worker()
    inbox = owner.get("/api/v1/notifications").json()
    kinds = {n["kind"] for n in inbox["items"]}
    assert {"scan_completed", "critical_finding", "high_finding"} <= kinds and inbox["unread"] >= 3
    first = inbox["items"][0]["id"]
    assert owner.post(f"/api/v1/notifications/{first}/read").status_code == 200
    assert owner.get("/api/v1/notifications").json()["unread"] == inbox["unread"] - 1
    owner.put("/api/v1/notifications/preferences", json={"kind": "scan_completed", "in_app": False})
    owner.post(f"/api/v1/organizations/{owner.org_id}/projects/{project['id']}/scans")
    run_worker()
    newest = owner.get("/api/v1/notifications").json()["items"]
    assert sum(1 for n in newest if n["kind"] == "scan_completed") == 1


def test_sarif_import_validates_schema(owner):
    project = owner.post(f"/api/v1/organizations/{owner.org_id}/projects", json={"name": "Imported", "source_type": "upload"}).json()
    url = f"/api/v1/organizations/{owner.org_id}/projects/{project['id']}/sarif-import"
    invalid = {"version": "2.1.0", "runs": [{"tool": {}}]}
    response = owner.post(url, files={"file": ("bad.sarif", json.dumps(invalid).encode(), "application/json")})
    assert response.status_code == 422 and response.json()["errors"]
    valid = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "ExternalTool", "rules": [{"id": "EXT1"}]}},
                                           "results": [{"ruleId": "EXT1", "level": "error", "message": {"text": "Bad thing"},
                                                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/a.py"},
                                                                                            "region": {"startLine": 4}}}]}]}]}
    imported = owner.post(url, files={"file": ("ok.sarif", json.dumps(valid).encode(), "application/json")})
    assert imported.status_code == 201 and imported.json()["new_findings"] == 1
    finding = owner.get(f"/api/v1/organizations/{owner.org_id}/findings").json()["items"][0]
    assert finding["rule_id"] == "ExternalTool:EXT1" and finding["severity"] == "high" and finding["line"] == 4


def test_github_network_failure_is_reported_not_500(owner):
    def unreachable(request):
        raise httpx.ConnectError("network down", request=request)

    gh.set_transport(httpx.MockTransport(unreachable))
    response = owner.post(f"/api/v1/organizations/{owner.org_id}/integrations/github", json={"token": TOKEN})
    assert response.status_code == 502
    assert "Could not reach GitHub" in response.json()["detail"]
