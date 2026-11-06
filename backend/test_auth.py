import pytest
from fastapi import HTTPException
from starlette.requests import Request

import database
from app import auth


@pytest.fixture
def auth_db(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "auth.sqlite")
    monkeypatch.setenv("SECURCODE_BOOTSTRAP_TOKEN", "bootstrap-test-token-is-over-32-chars")
    database.initialize_database()


def _request(client="127.0.0.1"):
    scope = {"type": "http", "method": "POST", "path": "/auth", "headers": [], "client": (client, 10000), "server": ("test", 80), "scheme": "http", "query_string": b""}
    return Request(scope)


def test_bootstrap_creates_only_one_admin_and_password_is_hashed(auth_db):
    result = auth.bootstrap(auth.BootstrapRequest(username="first-admin", password="correct-horse-battery-staple", bootstrap_token="bootstrap-test-token-is-over-32-chars"))
    assert result["user"]["role"] == "administrator"
    assert auth.get_user_for_token(result["access_token"])["username"] == "first-admin"
    with pytest.raises(HTTPException) as duplicate:
        auth.bootstrap(auth.BootstrapRequest(username="second-admin", password="correct-horse-battery-staple", bootstrap_token="bootstrap-test-token-is-over-32-chars"))
    assert duplicate.value.status_code == 409
    with database.get_connection() as connection:
        row = connection.execute("SELECT password_hash, password_salt FROM auth_users").fetchone()
        assert row["password_hash"] != "correct-horse-battery-staple"
        assert auth._valid_password("correct-horse-battery-staple", row["password_salt"], row["password_hash"])


def test_bootstrap_requires_long_configured_secret(auth_db, monkeypatch):
    monkeypatch.setenv("SECURCODE_BOOTSTRAP_TOKEN", "too-short")
    with pytest.raises(HTTPException) as denied:
        auth.bootstrap(auth.BootstrapRequest(username="first-admin", password="correct-horse-battery-staple", bootstrap_token="too-short"))
    assert denied.value.status_code == 403


def test_login_logout_and_role_matrix(auth_db):
    admin = auth.bootstrap(auth.BootstrapRequest(username="first-admin", password="correct-horse-battery-staple", bootstrap_token="bootstrap-test-token-is-over-32-chars"))
    user_request = _request()
    user_request.state.user = admin["user"]
    created = auth.create_user(auth.UserCreate(username="read-account", password="another-long-password-value", role="read_only"), user_request)
    assert created["role"] == "read_only"
    session = auth.login(auth.Credentials(username="read-account", password="another-long-password-value"), _request())
    assert auth.get_user_for_token(session["access_token"])["role"] == "read_only"
    assert auth.allowed_for_role("read_only", "GET", "/findings")
    assert not auth.allowed_for_role("read_only", "GET", "/auth/users")
    assert not auth.allowed_for_role("read_only", "PATCH", "/findings/1/0/status")
    assert not auth.allowed_for_role("developer", "POST", "/projects")
    assert auth.allowed_for_role("developer", "POST", "/projects/1/scan")
    assert not auth.allowed_for_role("security_analyst", "POST", "/auth/users")
    assert auth.allowed_for_role("administrator", "POST", "/auth/users")
    logout_request = _request()
    logout_request.state.access_token = session["access_token"]
    logout_request.state.user = session["user"]
    assert auth.logout(logout_request)["logged_out"]
    assert auth.get_user_for_token(session["access_token"]) is None
    second_session = auth.login(auth.Credentials(username="read-account", password="another-long-password-value"), _request())
    with pytest.raises(HTTPException) as self_disable:
        auth.update_user(admin["user"]["id"], auth.UserUpdate(disabled=True), user_request)
    assert self_disable.value.status_code == 400
    auth.update_user(created["id"], auth.UserUpdate(disabled=True), user_request)
    assert auth.get_user_for_token(second_session["access_token"]) is None


def test_invalid_login_does_not_create_session(auth_db):
    with pytest.raises(HTTPException) as denied:
        auth.login(auth.Credentials(username="missing", password="no-such-long-password"), _request())
    assert denied.value.status_code == 401
    with database.get_connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM auth_sessions").fetchone()[0] == 0


def test_expired_session_is_rejected(auth_db):
    session = auth.bootstrap(auth.BootstrapRequest(
        username="expiry-admin",
        password="correct-horse-battery-staple",
        bootstrap_token="bootstrap-test-token-is-over-32-chars",
    ))
    with database.get_connection() as connection:
        connection.execute(
            "UPDATE auth_sessions SET expires_at = ? WHERE token_hash = ?",
            ("2000-01-01T00:00:00+00:00", auth._token_hash(session["access_token"])),
        )

    assert auth.get_user_for_token(session["access_token"]) is None


def test_password_change_revokes_other_sessions_and_requires_current_password(auth_db):
    admin = auth.bootstrap(auth.BootstrapRequest(username="first-admin", password="correct-horse-battery-staple", bootstrap_token="bootstrap-test-token-is-over-32-chars"))
    second = auth.login(auth.Credentials(username="first-admin", password="correct-horse-battery-staple"), _request())
    request = _request()
    request.state.user = admin["user"]
    request.state.access_token = admin["access_token"]
    with pytest.raises(HTTPException) as wrong:
        auth.change_password(auth.PasswordChange(current_password="incorrect-password", new_password="new-password-long-enough"), request)
    assert wrong.value.status_code == 403
    auth.change_password(auth.PasswordChange(current_password="correct-horse-battery-staple", new_password="new-password-long-enough"), request)
    assert auth.get_user_for_token(admin["access_token"]) is not None
    assert auth.get_user_for_token(second["access_token"]) is None
    with pytest.raises(HTTPException):
        auth.login(auth.Credentials(username="first-admin", password="correct-horse-battery-staple"), _request())
    assert auth.login(auth.Credentials(username="first-admin", password="new-password-long-enough"), _request())["user"]["role"] == "administrator"


def test_login_rate_limit_applies_per_client(auth_db):
    credentials = auth.Credentials(username="missing", password="not-a-real-password-here")
    for _ in range(10):
        with pytest.raises(HTTPException) as denied:
            auth.login(credentials, _request("192.0.2.44"))
        assert denied.value.status_code == 401
    with pytest.raises(HTTPException) as limited:
        auth.login(credentials, _request("192.0.2.44"))
    assert limited.value.status_code == 429
