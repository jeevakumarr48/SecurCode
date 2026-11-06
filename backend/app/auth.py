"""Database-backed opaque bearer sessions and role authorization."""

from __future__ import annotations

from contextvars import ContextVar, Token
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import os
import secrets
import threading
import time

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from database import get_connection, record_audit_event

router = APIRouter(prefix="/auth", tags=["authentication"])
ROLES = {"administrator", "security_analyst", "developer", "read_only"}
SESSION_HOURS = 8
_login_lock = threading.Lock()
_login_attempts: dict[str, list[float]] = {}
_current_user: ContextVar[dict | None] = ContextVar("securcode_current_user", default=None)
_DUMMY_SALT = bytes(16)
_DUMMY_HASH = hashlib.scrypt(b"not-a-valid-securcode-password", salt=_DUMMY_SALT, n=2**14, r=8, p=1, dklen=32).hex()


class Credentials(BaseModel):
    username: str = Field(min_length=3, max_length=120)
    password: str = Field(min_length=12, max_length=256)


class BootstrapRequest(Credentials):
    bootstrap_token: str = Field(min_length=1, max_length=256)


class UserCreate(Credentials):
    role: str


class UserUpdate(BaseModel):
    role: str | None = None
    disabled: bool | None = None
    password: str | None = Field(default=None, min_length=12, max_length=256)


class PasswordChange(BaseModel):
    current_password: str = Field(min_length=12, max_length=256)
    new_password: str = Field(min_length=12, max_length=256)


def _password_hash(password: str, salt: bytes | None = None) -> tuple[str, str]:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return salt.hex(), digest.hex()


def _valid_password(password: str, salt_hex: str, digest_hex: str) -> bool:
    try:
        _salt, actual = _password_hash(password, bytes.fromhex(salt_hex))
        return hmac.compare_digest(actual, digest_hex)
    except (ValueError, TypeError):
        return False


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("ascii", errors="ignore")).hexdigest()


def bind_current_user(user: dict) -> Token:
    return _current_user.set(user)


def reset_current_user(token: Token) -> None:
    _current_user.reset(token)


def current_user() -> dict | None:
    return _current_user.get()


def project_access_allowed(project_id: int, user: dict | None = None) -> bool:
    user = current_user() if user is None else user
    if user is None or user["role"] == "administrator":
        return True
    with get_connection() as connection:
        return connection.execute(
            "SELECT 1 FROM project_members WHERE project_id = ? AND user_id = ?",
            (project_id, user["id"]),
        ).fetchone() is not None


def add_project_member(connection, project_id: int, user_id: int) -> None:
    connection.execute(
        "INSERT OR IGNORE INTO project_members(project_id, user_id) VALUES (?, ?)",
        (project_id, user_id),
    )


def _new_session(connection, user_id: int) -> str:
    connection.execute("DELETE FROM auth_sessions WHERE expires_at <= ?",
                       (datetime.now(timezone.utc).isoformat(),))
    token = secrets.token_urlsafe(48)
    expires = (datetime.now(timezone.utc) + timedelta(hours=SESSION_HOURS)).isoformat()
    connection.execute("INSERT INTO auth_sessions(user_id, token_hash, expires_at) VALUES (?, ?, ?)",
                       (user_id, _token_hash(token), expires))
    return token


def _make_admin(connection, username: str, password: str) -> int:
    salt, digest = _password_hash(password)
    cursor = connection.execute("INSERT INTO auth_users(username, password_salt, password_hash, role) VALUES (?, ?, ?, 'administrator')",
                                (username.strip(), salt, digest))
    return cursor.lastrowid


@router.post("/bootstrap", status_code=201)
def bootstrap(request: BootstrapRequest):
    """One-time first-admin creation, gated by a deployment-provided secret."""
    expected = os.getenv("SECURCODE_BOOTSTRAP_TOKEN", "")
    if len(expected) < 32 or not hmac.compare_digest(request.bootstrap_token, expected):
        raise HTTPException(status_code=403, detail="Bootstrap is unavailable or the token is invalid.")
    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        if connection.execute("SELECT 1 FROM auth_users LIMIT 1").fetchone():
            raise HTTPException(status_code=409, detail="Bootstrap has already been completed.")
        user_id = _make_admin(connection, request.username, request.password)
        token = _new_session(connection, user_id)
        record_audit_event(connection, request.username, "auth.bootstrap", "user", user_id, {"role": "administrator"})
    return {"access_token": token, "token_type": "bearer", "expires_in": SESSION_HOURS * 3600,
            "user": {"id": user_id, "username": request.username, "role": "administrator"}}


@router.post("/login")
def login(request: Credentials, client_request: Request):
    remote = client_request.client.host if client_request.client else "unknown"
    now = time.monotonic()
    with _login_lock:
        attempts = [moment for moment in _login_attempts.get(remote, []) if now - moment < 300]
        if len(attempts) >= 10:
            raise HTTPException(status_code=429, detail="Too many login attempts. Try again later.")
        attempts.append(now)
        if len(_login_attempts) > 4096:
            _login_attempts.pop(next(iter(_login_attempts)))
        _login_attempts[remote] = attempts
    with get_connection() as connection:
        row = connection.execute("SELECT id, username, password_salt, password_hash, role, disabled FROM auth_users WHERE username = ? COLLATE NOCASE",
                                 (request.username.strip(),)).fetchone()
        password_valid = (_valid_password(request.password, row["password_salt"], row["password_hash"])
                          if row else _valid_password(request.password, _DUMMY_SALT.hex(), _DUMMY_HASH))
        if not row or row["disabled"] or not password_valid:
            raise HTTPException(status_code=401, detail="Invalid username or password.")
        token = _new_session(connection, row["id"])
        record_audit_event(connection, row["username"], "auth.login", "user", row["id"], {})
    with _login_lock:
        _login_attempts.pop(remote, None)
    return {"access_token": token, "token_type": "bearer", "expires_in": SESSION_HOURS * 3600,
            "user": {"id": row["id"], "username": row["username"], "role": row["role"]}}


@router.get("/me")
def me(request: Request):
    return request.state.user


@router.post("/logout")
def logout(request: Request):
    token = request.state.access_token
    with get_connection() as connection:
        connection.execute("DELETE FROM auth_sessions WHERE token_hash = ?", (_token_hash(token),))
        record_audit_event(connection, request.state.user["username"], "auth.logout", "user", request.state.user["id"], {})
    return {"logged_out": True}


@router.post("/users", status_code=201)
def create_user(request: UserCreate, client_request: Request):
    if request.role not in ROLES:
        raise HTTPException(status_code=422, detail="Unsupported role.")
    with get_connection() as connection:
        try:
            salt, digest = _password_hash(request.password)
            cursor = connection.execute("INSERT INTO auth_users(username, password_salt, password_hash, role) VALUES (?, ?, ?, ?)",
                                        (request.username.strip(), salt, digest, request.role))
        except Exception as error:
            if "UNIQUE" in str(error).upper():
                raise HTTPException(status_code=409, detail="Username already exists.") from None
            raise
        record_audit_event(connection, client_request.state.user["username"], "auth.user_created", "user", cursor.lastrowid,
                           {"role": request.role})
        return {"id": cursor.lastrowid, "username": request.username.strip(), "role": request.role}


@router.get("/users")
def list_users():
    with get_connection() as connection:
        rows = connection.execute("SELECT id, username, role, disabled, created_at FROM auth_users ORDER BY username COLLATE NOCASE").fetchall()
    return {"users": [dict(row) for row in rows]}


@router.patch("/users/{user_id}")
def update_user(user_id: int, request: UserUpdate, client_request: Request):
    if request.role is None and request.disabled is None and request.password is None:
        raise HTTPException(status_code=400, detail="Provide a role, disabled state, or password to update.")
    if request.role is not None and request.role not in ROLES:
        raise HTTPException(status_code=422, detail="Unsupported role.")
    if user_id == client_request.state.user["id"] and request.role not in {None, "administrator"}:
        raise HTTPException(status_code=400, detail="Administrators cannot remove their own administrator role.")
    if user_id == client_request.state.user["id"] and request.disabled:
        raise HTTPException(status_code=400, detail="Administrators cannot disable their own account.")
    updates = {}
    if request.role is not None:
        updates["role"] = request.role
    if request.disabled is not None:
        updates["disabled"] = int(request.disabled)
    if request.password is not None:
        salt, digest = _password_hash(request.password)
        updates["password_salt"] = salt
        updates["password_hash"] = digest
    assignments = ", ".join(f"{name} = ?" for name in updates)
    with get_connection() as connection:
        cursor = connection.execute(f"UPDATE auth_users SET {assignments} WHERE id = ?", (*updates.values(), user_id))
        if not cursor.rowcount:
            raise HTTPException(status_code=404, detail="User not found.")
        if request.disabled or request.password is not None:
            connection.execute("DELETE FROM auth_sessions WHERE user_id = ?", (user_id,))
        record_audit_event(
            connection,
            client_request.state.user["username"],
            "auth.user_updated",
            "user",
            user_id,
            {
                "changed_fields": sorted(
                    {
                        "password" if name in {"password_hash", "password_salt"} else name
                        for name in updates
                    }
                )
            },
        )
        row = connection.execute("SELECT id, username, role, disabled FROM auth_users WHERE id = ?", (user_id,)).fetchone()
    return dict(row)


@router.post("/password")
def change_password(request: PasswordChange, client_request: Request):
    with get_connection() as connection:
        row = connection.execute("SELECT password_salt, password_hash FROM auth_users WHERE id = ?",
                                 (client_request.state.user["id"],)).fetchone()
        if not row or not _valid_password(request.current_password, row["password_salt"], row["password_hash"]):
            raise HTTPException(status_code=403, detail="Current password is incorrect.")
        salt, digest = _password_hash(request.new_password)
        connection.execute("UPDATE auth_users SET password_salt = ?, password_hash = ? WHERE id = ?",
                           (salt, digest, client_request.state.user["id"]))
        connection.execute("DELETE FROM auth_sessions WHERE user_id = ? AND token_hash <> ?",
                           (client_request.state.user["id"], _token_hash(client_request.state.access_token)))
        record_audit_event(connection, client_request.state.user["username"], "auth.password_changed", "user",
                           client_request.state.user["id"], {})
    return {"password_changed": True}


def get_user_for_token(token: str):
    with get_connection() as connection:
        row = connection.execute("""SELECT u.id, u.username, u.role, u.disabled FROM auth_sessions s
            JOIN auth_users u ON u.id = s.user_id WHERE s.token_hash = ? AND s.expires_at > ?""",
            (_token_hash(token), datetime.now(timezone.utc).isoformat())).fetchone()
    if not row or row["disabled"]:
        return None
    return {"id": row["id"], "username": row["username"], "role": row["role"]}


def allowed_for_role(role: str, method: str, path: str) -> bool:
    if path == "/auth/logout":
        return True
    if path == "/auth/password":
        return role in ROLES
    if path.startswith("/auth/users"):
        return role == "administrator"
    if method in {"GET", "HEAD", "OPTIONS"}:
        return True
    if role in {"administrator", "security_analyst"}:
        return True
    if role == "developer":
        return (path in {"/scan"} or path.endswith("/scan") or "/comments" in path
                or path.endswith("/assignee") or path.endswith("/read"))
    return False
