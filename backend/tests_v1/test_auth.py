"""Authentication, session, password recovery and MFA behaviour."""

import time

from sqlalchemy import select

from app.v1 import db as v1_db
from app.v1.models import AuditEvent, User, UserSession
from app.v1.security import totp_code

from .conftest import PASSWORD


def test_register_creates_session_cookie_httponly_and_no_token_in_body(make_client):
    client = make_client()
    response = client.post("/api/v1/auth/register", json={"email": "Dev@Example.com", "password": PASSWORD})
    assert response.status_code == 201
    body = response.json()
    assert body["user"]["email"] == "dev@example.com"
    cookie = response.headers["set-cookie"]
    assert "sc_session=" in cookie and "HttpOnly" in cookie and "SameSite=lax" in cookie
    session_value = response.cookies.get("sc_session")
    assert session_value and session_value not in response.text


def test_password_is_stored_with_argon2id(make_client):
    make_client().register("hash@example.com")
    with v1_db.SessionLocal() as db:
        user = db.execute(select(User).where(User.email == "hash@example.com")).scalar_one()
        assert user.password_hash.startswith("$argon2id$")
        assert PASSWORD not in user.password_hash


def test_weak_password_rejected(make_client):
    response = make_client().post("/api/v1/auth/register", json={"email": "weak@example.com", "password": "password1234"})
    assert response.status_code == 422


def test_duplicate_registration_rejected(make_client):
    make_client().register("dup@example.com")
    response = make_client().post("/api/v1/auth/register", json={"email": "DUP@example.com", "password": PASSWORD})
    assert response.status_code == 409


def test_login_logout_and_generic_errors(make_client):
    make_client().register("login@example.com")
    client = make_client()
    unknown = client.login("nobody@example.com")
    wrong = client.login("login@example.com", "Wrong-Password-123")
    assert unknown.status_code == wrong.status_code == 401
    assert unknown.json()["detail"] == wrong.json()["detail"]
    ok = client.login("login@example.com")
    assert ok.status_code == 200 and ok.json()["status"] == "authenticated"
    assert client.get("/api/v1/auth/session").status_code == 200
    assert client.post("/api/v1/auth/logout").status_code == 200
    assert client.get("/api/v1/auth/session").status_code == 401


def test_csrf_required_for_state_changing_requests(make_client):
    client = make_client()
    client.register("csrf@example.com")
    token = client.csrf
    client.csrf = None
    assert client.post("/api/v1/organizations", json={"name": "No CSRF"}).status_code == 403
    assert client.post("/api/v1/organizations", json={"name": "Bad"}, headers={"X-CSRF-Token": "forged"}).status_code == 403
    client.csrf = token
    assert client.post("/api/v1/organizations", json={"name": "With CSRF"}).status_code == 201


def test_login_rotates_session_identifier(make_client):
    client = make_client()
    client.register("fixation@example.com")
    first = client.http.cookies.get("sc_session")
    client.login("fixation@example.com")
    second = client.http.cookies.get("sc_session")
    assert first != second
    with v1_db.SessionLocal() as db:
        sessions = db.execute(select(UserSession)).scalars().all()
        assert sum(1 for s in sessions if s.revoked_at is None) == 1


def test_account_lockout_after_repeated_failures(make_client, monkeypatch):
    make_client().register("lock@example.com")
    client = make_client()
    statuses = [client.login("lock@example.com", "Wrong-Password-123").status_code for _ in range(8)]
    assert statuses[-1] == 401
    assert client.login("lock@example.com").status_code == 423
    with v1_db.SessionLocal() as db:
        actions = [e.action for e in db.execute(select(AuditEvent)).scalars()]
    assert "auth.account_locked" in actions and "auth.login_failed" in actions


def test_login_rate_limited_per_identifier(make_client):
    client = make_client()
    statuses = [client.login("ratelimited@example.com", "Wrong-Password-123").status_code for _ in range(11)]
    assert statuses[:10] == [401] * 10
    assert statuses[10] == 429


def test_session_listing_and_revocation(make_client):
    first = make_client()
    first.register("multi@example.com")
    second = make_client()
    second.login("multi@example.com")
    sessions = first.get("/api/v1/auth/sessions").json()["items"]
    assert len(sessions) == 2
    other = next(s for s in sessions if not s["current"])
    assert first.delete(f"/api/v1/auth/sessions/{other['id']}").status_code == 200
    assert second.get("/api/v1/auth/session").status_code == 401
    assert first.get("/api/v1/auth/session").status_code == 200


def test_password_change_revokes_other_sessions(make_client):
    first = make_client()
    first.register("change@example.com")
    second = make_client()
    second.login("change@example.com")
    response = first.post("/api/v1/auth/password/change",
                          json={"current_password": PASSWORD, "new_password": "Another-Strong-Pass-77"})
    assert response.status_code == 200 and response.json()["other_sessions_revoked"] == 1
    assert second.get("/api/v1/auth/session").status_code == 401
    assert make_client().login("change@example.com", "Another-Strong-Pass-77").status_code == 200


def test_password_reset_flow_is_single_use_and_revokes_sessions(make_client):
    owner = make_client()
    owner.register("reset@example.com")
    anon = make_client()
    unknown = anon.post("/api/v1/auth/password/forgot", json={"email": "missing@example.com"})
    known = anon.post("/api/v1/auth/password/forgot", json={"email": "reset@example.com"})
    assert unknown.status_code == known.status_code == 202
    link = known.json()["development_reset_link"]
    assert unknown.json()["development_reset_link"] is None
    token = link.split("token=", 1)[1]
    new_password = "Brand-New-Password-91"
    assert anon.post("/api/v1/auth/password/reset", json={"token": token, "new_password": new_password}).status_code == 200
    assert anon.post("/api/v1/auth/password/reset", json={"token": token, "new_password": new_password}).status_code == 400
    assert owner.get("/api/v1/auth/session").status_code == 401
    assert make_client().login("reset@example.com", new_password).status_code == 200


def test_totp_mfa_enrolment_and_login_challenge(make_client):
    client = make_client()
    client.register("mfa@example.com")
    setup = client.post("/api/v1/auth/mfa/setup").json()
    secret = setup["secret"]
    assert setup["otpauth_uri"].startswith("otpauth://totp/")
    assert client.post("/api/v1/auth/mfa/enable", json={"code": "000000"}).status_code == 400
    assert client.post("/api/v1/auth/mfa/enable", json={"code": totp_code(secret)}).status_code == 200

    second = make_client()
    response = second.login("mfa@example.com")
    assert response.json()["status"] == "mfa_required"
    pending_csrf = response.json()["csrf_token"]
    assert "user" not in response.json()
    # A pending-MFA session cannot use the API.
    assert second.get("/api/v1/organizations").status_code == 401
    code = totp_code(secret, time.time() + 30)  # next window: never the code used at enrolment
    verified = second.http.post("/api/v1/auth/mfa/verify", json={"code": code})
    assert verified.status_code == 403  # CSRF still enforced on the challenge
    verified = second.http.post("/api/v1/auth/mfa/verify", json={"code": code}, headers={"X-CSRF-Token": pending_csrf})
    assert verified.status_code == 200, verified.text
    second.absorb(verified)
    assert second.get("/api/v1/organizations").status_code == 200
    replay = make_client()
    csrf = replay.login("mfa@example.com").json()["csrf_token"]
    assert replay.http.post("/api/v1/auth/mfa/verify", json={"code": code}, headers={"X-CSRF-Token": csrf}).status_code == 401


def test_legacy_scrypt_hash_is_accepted_and_upgraded(make_client):
    import hashlib

    salt = bytes(range(16))
    digest = hashlib.scrypt(PASSWORD.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32).hex()
    with v1_db.SessionLocal() as db:
        db.add(User(email="legacy@legacy.example.com", legacy_username="admin", display_name="admin",
                    password_hash=f"scrypt${salt.hex()}${digest}", is_platform_admin=True))
        db.commit()
    client = make_client()
    assert client.login("admin").status_code == 200
    with v1_db.SessionLocal() as db:
        user = db.execute(select(User).where(User.legacy_username == "admin")).scalar_one()
        assert user.password_hash.startswith("$argon2id$")


def test_security_headers_and_request_id(make_client):
    response = make_client().get("/api/v1/health/live")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert len(response.headers["x-request-id"]) >= 8


def test_oversized_body_rejected(make_client):
    response = make_client().http.post(
        "/api/v1/auth/login", content=b"x" * 1_100_000, headers={"content-type": "application/json"}
    )
    assert response.status_code == 413
