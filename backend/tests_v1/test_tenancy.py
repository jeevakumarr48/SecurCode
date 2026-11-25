"""Cross-tenant isolation, IDOR and role enforcement."""

import re

import pytest

from .conftest import invite_and_join
from .helpers import create_upload_project, run_worker, upload_and_scan, zip_directory


@pytest.fixture
def two_tenants(owner, make_client):
    """Tenant A has a scanned project; tenant B is an unrelated organization."""
    project = create_upload_project(owner, "Tenant A secret project")
    scan = upload_and_scan(owner, project["id"], zip_directory("demo-vulnerable-app"))
    run_worker()
    finding = owner.get(f"/api/v1/organizations/{owner.org_id}/findings").json()["items"][0]
    invitation = owner.post(f"/api/v1/organizations/{owner.org_id}/invitations",
                            json={"email": "pending@alpha.example.com", "role": "viewer"}).json()
    review = owner.post(f"/api/v1/organizations/{owner.org_id}/findings/{finding['id']}/reviews",
                        json={"kind": "false_positive", "justification": "Test fixture code that is never deployed."}).json()
    schedule = owner.post(f"/api/v1/organizations/{owner.org_id}/schedules",
                          json={"project_id": project["id"], "frequency": "daily", "hour": 3}).json()
    attacker = make_client()
    attacker.register("attacker@beta.example.com")
    beta = attacker.post("/api/v1/organizations", json={"name": "Beta Corp"}).json()
    attacker.org_id = beta["id"]
    ids = {"org_id": owner.org_id, "project_id": project["id"], "scan_id": scan["id"], "finding_id": finding["id"],
           "invitation_id": invitation["id"], "review_id": review["id"], "schedule_id": schedule["id"],
           "user_id": owner.user["id"], "other_scan_id": scan["id"], "integration_id": "0" * 32,
           "owner": "octo", "repo": "repo", "kind": "project"}
    return owner, attacker, ids


def _all_routes(app):
    """Enumerate every documented route (robust to nested/lazily included routers)."""
    for path, operations in app.openapi()["paths"].items():
        for method in operations:
            yield method.upper(), path


def _org_routes(app):
    for method, path in _all_routes(app):
        if path.startswith("/api/v1/organizations/{org_id}"):
            yield method, path


def _fill(path, ids, org_override=None):
    values = dict(ids)
    if org_override:
        values["org_id"] = org_override
    return re.sub(r"\{(\w+)\}", lambda m: values.get(m.group(1), "x"), path)


def _call(client, method, url):
    if method == "GET":
        return client.get(url, params={"project_id": None})
    if method == "DELETE":
        return client.http.request("DELETE", url, headers={"X-CSRF-Token": client.csrf}, json={"confirm_name": "Tenant A secret project"})
    body = {"name": "x" * 5, "role": "viewer", "email": "x@beta.example.com", "status": "triaged", "body": "hi",
            "kind": "false_positive", "justification": "j" * 30, "approve": True, "changes": {}, "reason": "attack",
            "project_id": ids_cache.get("project_id"), "frequency": "daily", "hour": 1, "finding_ids": [ids_cache.get("finding_id")],
            "token": "t" * 30, "confirm_name": "Tenant A secret project"}
    return getattr(client, method.lower())(url, json=body)


ids_cache: dict = {}


def test_every_org_route_rejects_foreign_org(app, two_tenants):
    owner, attacker, ids = two_tenants
    ids_cache.update(ids)
    checked = 0
    for method, path in _org_routes(app):
        response = _call(attacker, method, _fill(path, ids))
        # Exactly 404: indistinguishable from a non-existent organization.
        assert response.status_code == 404, f"{method} {path} -> {response.status_code}: {response.text[:200]}"
        assert "Tenant A" not in response.text
        checked += 1
    assert checked > 50


def test_foreign_object_ids_under_own_org_are_not_found(app, two_tenants):
    owner, attacker, ids = two_tenants
    ids_cache.update(ids)
    object_routes = [(m, p) for m, p in _org_routes(app) if re.search(r"\{(project_id|scan_id|finding_id|invitation_id|review_id|schedule_id|other_scan_id)\}", p)]
    for method, path in object_routes:
        response = _call(attacker, method, _fill(path, ids, org_override=attacker.org_id))
        assert response.status_code in {404, 422}, f"{method} {path} -> {response.status_code}: {response.text[:200]}"
    # Listing endpoints in the attacker's org return nothing from tenant A.
    base = f"/api/v1/organizations/{attacker.org_id}"
    for url in ("/projects", "/scans", "/findings", "/reviews", "/schedules"):
        body = attacker.get(base + url).json()
        assert body.get("items") == [] or body.get("total") == 0, url
    own_audit = attacker.get(base + "/audit-events").json()["items"]
    assert own_audit and all(e["actor_email"] == "attacker@beta.example.com" for e in own_audit)
    assert all(ids["project_id"] != e["project_id"] for e in own_audit)
    export = attacker.get(f"{base}/exports/findings", params={"format": "json"}).json()
    assert export["count"] == 0
    assert attacker.get(f"{base}/exports/findings", params={"format": "json", "project_id": ids["project_id"]}).status_code == 404
    assert attacker.get(f"{base}/exports/findings", params={"format": "csv", "scan_id": ids["scan_id"]}).status_code == 404
    dashboard = attacker.get(f"{base}/analytics/dashboard").json()
    assert dashboard["totals"]["active_findings"] == 0 and dashboard["totals"]["projects"] == 0


def test_foreign_tenant_data_unchanged_after_attack(app, two_tenants):
    owner, attacker, ids = two_tenants
    ids_cache.update(ids)
    for method, path in _org_routes(app):
        _call(attacker, method, _fill(path, ids))
        _call(attacker, method, _fill(path, ids, org_override=attacker.org_id))
    base = f"/api/v1/organizations/{ids['org_id']}"
    assert owner.get(f"{base}/projects/{ids['project_id']}").status_code == 200
    finding = owner.get(f"{base}/findings/{ids['finding_id']}").json()
    assert finding["status"] == "open" and finding["assignee_id"] is None
    members = owner.get(f"{base}/members").json()["items"]
    assert [m["email"] for m in members] == ["owner@alpha.example.com"]


def test_guessed_ids_and_non_members(owner, make_client):
    outsider = make_client()
    outsider.register("guess@gamma.example.com")
    for org_id in (owner.org_id, "0" * 32, "%2e%2e%2fadmin", "x" * 40):
        assert outsider.get(f"/api/v1/organizations/{org_id}").status_code in {404, 422}
    assert outsider.get(f"/api/v1/organizations/{owner.org_id}/findings/{'f' * 32}").status_code == 404


def test_unauthenticated_requests_rejected(app, make_client):
    anonymous = make_client()
    for method, path in _org_routes(app):
        response = anonymous.http.request(method, path.replace("{org_id}", "a" * 32).replace("{", "").replace("}", ""))
        assert response.status_code in {401, 403, 422}, f"{method} {path} -> {response.status_code}"


ROLE_EXPECTATIONS = {
    # (method, path template, body) -> roles allowed
    "create_project": ("post", "/projects", {"name": "Role project", "source_type": "upload"}, {"owner", "admin"}),
    "update_policy": ("put", "/policy", {"changes": {"minimum_severity": "low"}, "reason": "role test"}, {"owner", "admin", "security_admin"}),
    "invite": ("post", "/invitations", {"email": "new@alpha.example.com", "role": "viewer"}, {"owner", "admin"}),
    "audit": ("get", "/audit-events", None, {"owner", "admin", "security_admin"}),
    "export": ("get", "/exports/findings?format=json", None, {"owner", "admin", "security_admin", "security_analyst"}),
    "org_update": ("patch", "", {"name": "Renamed Org"}, {"owner", "admin"}),
}


@pytest.mark.parametrize("role", ["admin", "security_admin", "security_analyst", "developer", "viewer"])
def test_role_permission_matrix_is_enforced_server_side(owner, make_client, role):
    member = invite_and_join(owner, make_client, f"{role}@alpha.example.com", role)
    base = f"/api/v1/organizations/{owner.org_id}"
    for name, (method, path, body, allowed) in ROLE_EXPECTATIONS.items():
        kwargs = {"json": body} if body is not None else {}
        response = getattr(member, method)(base + path, **kwargs)
        if role in allowed:
            assert response.status_code < 400, f"{role} {name}: {response.status_code} {response.text}"
        else:
            assert response.status_code == 403, f"{role} {name}: {response.status_code}"


def test_admin_cannot_escalate_to_owner_or_demote_owner(owner, make_client):
    admin = invite_and_join(owner, make_client, "admin@alpha.example.com", "admin")
    viewer = invite_and_join(owner, make_client, "viewer@alpha.example.com", "viewer")
    base = f"/api/v1/organizations/{owner.org_id}"
    assert admin.patch(f"{base}/members/{viewer.user['id']}", json={"role": "owner"}).status_code == 403
    assert admin.patch(f"{base}/members/{owner.user['id']}", json={"role": "viewer"}).status_code == 403
    assert admin.post(f"{base}/invitations", json={"email": "x@alpha.example.com", "role": "admin"}).status_code == 403
    assert admin.patch(f"{base}/members/{viewer.user['id']}", json={"role": "developer"}).status_code == 200
    # Last owner cannot be removed or demoted.
    assert owner.patch(f"{base}/members/{owner.user['id']}", json={"role": "admin"}).status_code == 409
    assert owner.delete(f"{base}/members/{owner.user['id']}").status_code == 409


def test_platform_admin_is_not_an_org_member(owner, make_client):
    from sqlalchemy import update

    from app.v1 import db as v1_db
    from app.v1.models import User

    staff = make_client()
    staff.register("staff@securcode.example.com")
    with v1_db.SessionLocal() as db:
        db.execute(update(User).where(User.email == "staff@securcode.example.com").values(is_platform_admin=True))
        db.commit()
    assert staff.get(f"/api/v1/organizations/{owner.org_id}/findings").status_code == 404
    overview = staff.get("/api/v1/admin/overview")
    assert overview.status_code == 200 and overview.json()["audit_chain"]["valid"] is True
    assert owner.get("/api/v1/admin/overview").status_code == 403
    orgs = staff.get("/api/v1/admin/organizations").json()["items"]
    assert orgs[0]["name"] == "Alpha Security" and "findings" not in orgs[0]
    suspend = staff.post(f"/api/v1/admin/organizations/{owner.org_id}/suspend", json={"reason": "abuse report"})
    assert suspend.status_code == 200
    assert owner.get(f"/api/v1/organizations/{owner.org_id}/projects").status_code == 423
    events = staff.get("/api/v1/admin/security-events", params={"action": "admin."}).json()["items"]
    assert any(e["action"] == "admin.org_suspended" for e in events)


def test_invitation_token_single_use_and_email_bound(owner, make_client):
    response = owner.post(f"/api/v1/organizations/{owner.org_id}/invitations", json={"email": "bound@alpha.example.com", "role": "developer"})
    token = response.json()["accept_link"].split("token=")[1]
    preview = make_client().post("/api/v1/invitations/preview", json={"token": token}).json()
    assert preview == {"organization_name": "Alpha Security", "role": "developer", "email": "bound@alpha.example.com", "has_account": False}
    wrong = make_client()
    wrong.register("someoneelse@alpha.example.com")
    assert wrong.post("/api/v1/invitations/accept", json={"token": token}).status_code == 403
    right = make_client()
    right.register("bound@alpha.example.com")
    assert right.post("/api/v1/invitations/accept", json={"token": token}).status_code == 200
    assert right.post("/api/v1/invitations/accept", json={"token": token}).status_code == 404
    # Resend rotates the token; revoke invalidates it.
    resent = owner.post(f"/api/v1/organizations/{owner.org_id}/invitations", json={"email": "later@alpha.example.com", "role": "viewer"}).json()
    old_token = resent["accept_link"].split("token=")[1]
    rotated = owner.post(f"/api/v1/organizations/{owner.org_id}/invitations/{resent['id']}/resend").json()
    assert rotated["send_count"] == 2
    assert make_client().post("/api/v1/invitations/preview", json={"token": old_token}).status_code == 404
    owner.delete(f"/api/v1/organizations/{owner.org_id}/invitations/{resent['id']}")
    new_token = rotated["accept_link"].split("token=")[1]
    assert make_client().post("/api/v1/invitations/preview", json={"token": new_token}).status_code == 404


def test_user_can_belong_to_and_switch_between_orgs(owner, make_client):
    member = invite_and_join(owner, make_client, "multi@alpha.example.com", "viewer")
    own = member.post("/api/v1/organizations", json={"name": "Member Side Project"}).json()
    session = member.get("/api/v1/auth/session").json()
    assert {o["name"] for o in session["organizations"]} == {"Alpha Security", "Member Side Project"}
    switched = member.post("/api/v1/auth/me/active-organization", json={"org_id": owner.org_id}).json()
    assert switched["active_org_id"] == owner.org_id
    roles = {o["id"]: o["role"] for o in switched["organizations"]}
    assert roles == {owner.org_id: "viewer", own["id"]: "owner"}
    assert member.post("/api/v1/auth/me/active-organization", json={"org_id": "f" * 32}).status_code == 404


def test_audit_chain_records_actor_and_detects_tampering(owner):
    from sqlalchemy import select, update

    from app.v1 import audit
    from app.v1 import db as v1_db
    from app.v1.models import AuditEvent

    create_upload_project(owner)
    events = owner.get(f"/api/v1/organizations/{owner.org_id}/audit-events").json()["items"]
    created = next(e for e in events if e["action"] == "project.created")
    assert created["actor_email"] == "owner@alpha.example.com" and created["request_id"]
    with v1_db.SessionLocal() as db:
        assert audit.verify_chain(db)["valid"] is True
        target = db.execute(select(AuditEvent).where(AuditEvent.action == "project.created")).scalar_one()
        db.execute(update(AuditEvent).where(AuditEvent.id == target.id).values(action="project.renamed"))
        db.commit()
        result = audit.verify_chain(db)
    assert result["valid"] is False and result["broken_at"] == target.id
    # No API route can modify or delete audit events.
    from app.main import app

    for method, path in _all_routes(app):
        if "audit" in path:
            assert method == "GET", path
