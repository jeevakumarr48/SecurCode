"""Registration, login, sessions, password recovery, email verification and MFA."""

from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, EmailStr, Field, field_validator
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from .. import audit
from ..db import get_db, utcnow
from ..deps import (
    SESSION_COOKIE,
    AuthContext,
    client_ip,
    current_auth,
    current_auth_mfa_pending,
)
from ..models import Membership, OneTimeToken, Organization, User, UserSession
from ..permissions import permissions_for
from ..security import (
    decrypt_secret,
    encrypt_secret,
    equalise_timing,
    hash_password,
    new_token,
    new_totp_secret,
    token_digest,
    totp_uri,
    validate_password_policy,
    verify_password,
    verify_totp,
)
from ..services.common import hit_rate_limit, send_email
from ..settings import platform_settings

router = APIRouter(prefix="/auth", tags=["authentication"])
GENERIC_LOGIN_ERROR = "Email or password is incorrect."


def normalise_email(value: str) -> str:
    return value.strip().lower()


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=256)
    display_name: str = Field(default="", max_length=120)


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=256)


class CodeRequest(BaseModel):
    code: str = Field(min_length=6, max_length=6)


class TokenRequest(BaseModel):
    token: str = Field(min_length=20, max_length=200)


class EmailRequest(BaseModel):
    email: EmailStr


class ResetRequest(BaseModel):
    token: str = Field(min_length=20, max_length=200)
    new_password: str = Field(min_length=12, max_length=256)


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=12, max_length=256)


class MfaDisableRequest(BaseModel):
    password: str = Field(min_length=1, max_length=256)
    code: str = Field(min_length=6, max_length=6)


class ProfileUpdate(BaseModel):
    display_name: str = Field(min_length=1, max_length=120)

    @field_validator("display_name")
    @classmethod
    def _strip(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Display name cannot be blank.")
        return value


class ActiveOrgRequest(BaseModel):
    org_id: str = Field(min_length=1, max_length=32)


# --- helpers --------------------------------------------------------------------

def _set_session_cookie(response: Response, token: str, max_age: int) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=max_age,
        httponly=True,
        secure=platform_settings.cookie_secure,
        samesite=platform_settings.cookie_samesite,
        domain=platform_settings.cookie_domain,
        path="/",
    )


def _clear_session_cookie(response: Response) -> None:
    response.delete_cookie(
        SESSION_COOKIE,
        path="/",
        domain=platform_settings.cookie_domain,
        secure=platform_settings.cookie_secure,
        httponly=True,
        samesite=platform_settings.cookie_samesite,
    )


def _create_session(db: Session, request: Request, response: Response, user: User, mfa_pending: bool) -> UserSession:
    # Session fixation defence: any session presented with this request is revoked
    # and a brand-new random identifier is issued.
    presented = request.cookies.get(SESSION_COOKIE)
    if presented:
        db.execute(
            update(UserSession)
            .where(UserSession.token_hash == token_digest(presented), UserSession.revoked_at.is_(None))
            .values(revoked_at=utcnow())
        )
    token = new_token()
    now = utcnow()
    hours = platform_settings.session_hours
    session = UserSession(
        user_id=user.id,
        token_hash=token_digest(token),
        csrf_token=new_token(24),
        created_at=now,
        last_seen_at=now,
        expires_at=now + (timedelta(minutes=10) if mfa_pending else timedelta(hours=hours)),
        ip_address=client_ip(request),
        user_agent=(request.headers.get("user-agent") or "")[:300],
        mfa_pending=mfa_pending,
    )
    db.add(session)
    db.flush()
    _set_session_cookie(response, token, 600 if mfa_pending else hours * 3600)
    return session


def _issue_one_time_token(db: Session, user: User, purpose: str, lifetime: timedelta) -> str:
    db.execute(
        update(OneTimeToken)
        .where(OneTimeToken.user_id == user.id, OneTimeToken.purpose == purpose, OneTimeToken.used_at.is_(None))
        .values(used_at=utcnow())
    )
    token = new_token()
    db.add(OneTimeToken(user_id=user.id, purpose=purpose, token_hash=token_digest(token), expires_at=utcnow() + lifetime))
    db.flush()
    return token


def _consume_one_time_token(db: Session, token: str, purpose: str) -> User:
    record = db.execute(
        select(OneTimeToken).where(OneTimeToken.token_hash == token_digest(token), OneTimeToken.purpose == purpose)
    ).scalar_one_or_none()
    if record is None or record.used_at is not None or record.expires_at <= utcnow():
        raise HTTPException(status_code=400, detail="This link is invalid or has expired.")
    record.used_at = utcnow()
    user = db.get(User, record.user_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=400, detail="This link is invalid or has expired.")
    return user


def _send_verification(db: Session, user: User) -> str | None:
    token = _issue_one_time_token(db, user, "verify_email", timedelta(hours=48))
    link = f"{platform_settings.public_app_url}/verify-email?token={token}"
    result = send_email(user.email, "Verify your SecurCode email", f"Confirm your email address:\n{link}\n\nThis link expires in 48 hours.")
    return link if (result.mode == "console" and not platform_settings.is_production) else None


def user_payload(db: Session, user: User, session: UserSession | None = None) -> dict:
    rows = db.execute(
        select(Membership, Organization)
        .join(Organization, Organization.id == Membership.org_id)
        .where(Membership.user_id == user.id)
        .order_by(Organization.name)
    ).all()
    organizations = [
        {
            "id": org.id,
            "name": org.name,
            "slug": org.slug,
            "status": org.status,
            "role": membership.role,
            "is_demo": org.is_demo,
            "permissions": permissions_for(membership.role),
        }
        for membership, org in rows
    ]
    active = session.active_org_id if session else None
    if active not in {org["id"] for org in organizations}:
        active = organizations[0]["id"] if organizations else None
    return {
        "user": {
            "id": user.id,
            "email": user.email,
            "display_name": user.display_name,
            "email_verified": user.email_verified_at is not None,
            "mfa_enabled": user.mfa_enabled,
            "is_platform_admin": user.is_platform_admin,
            "created_at": user.created_at.isoformat(),
        },
        "organizations": organizations,
        "active_org_id": active,
        "csrf_token": session.csrf_token if session else None,
    }


# --- endpoints -----------------------------------------------------------------

@router.post("/register", status_code=201)
def register(body: RegisterRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    if not platform_settings.registration_open:
        raise HTTPException(status_code=403, detail="Self-service registration is disabled on this instance.")
    hit_rate_limit(f"register:{client_ip(request)}", limit=10, window_seconds=3600)
    email = normalise_email(body.email)
    try:
        validate_password_policy(body.password, email)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from None
    if db.execute(select(User.id).where(User.email == email)).first():
        # Do not reveal account existence beyond what a unique email requires.
        raise HTTPException(status_code=409, detail="An account with this email cannot be created.")
    user = User(
        email=email,
        display_name=body.display_name.strip() or email.split("@", 1)[0],
        password_hash=hash_password(body.password),
        password_changed_at=utcnow(),
    )
    db.add(user)
    db.flush()
    audit.record(db, "auth.register", actor=user, resource_type="user", resource_id=user.id, scope="platform")
    dev_link = None
    if platform_settings.require_email_verification:
        dev_link = _send_verification(db, user)
        db.commit()
        return {"status": "verification_required", "development_verification_link": dev_link}
    session = _create_session(db, request, response, user, mfa_pending=False)
    db.commit()
    return {"status": "registered", **user_payload(db, user, session)}


@router.post("/login")
def login(body: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    ip = client_ip(request)
    identifier = normalise_email(body.email)
    hit_rate_limit(f"login-ip:{ip}", limit=30, window_seconds=300)
    hit_rate_limit(f"login-id:{identifier}", limit=10, window_seconds=300)
    user = db.execute(select(User).where(User.email == identifier)).scalar_one_or_none()
    if user is None and "@" not in identifier:
        user = db.execute(select(User).where(User.legacy_username == body.email.strip())).scalar_one_or_none()
    now = utcnow()
    if user is None:
        equalise_timing(body.password)
        audit.record(db, "auth.login_failed", metadata={"reason": "unknown_account"}, scope="platform")
        db.commit()
        raise HTTPException(status_code=401, detail=GENERIC_LOGIN_ERROR)
    if user.locked_until and user.locked_until > now:
        equalise_timing(body.password)
        audit.record(db, "auth.login_blocked", actor=user, resource_type="user", resource_id=user.id, scope="platform")
        db.commit()
        raise HTTPException(status_code=423, detail="Account temporarily locked after repeated failures. Try again later.")
    valid, needs_rehash = verify_password(body.password, user.password_hash)
    if not valid or not user.is_active:
        if valid and not user.is_active:
            reason = "inactive"
        else:
            reason = "bad_password"
            user.failed_login_count += 1
            if user.failed_login_count >= platform_settings.login_max_failures:
                user.locked_until = now + timedelta(minutes=platform_settings.lockout_minutes)
                user.failed_login_count = 0
                audit.record(db, "auth.account_locked", actor=user, resource_type="user", resource_id=user.id, scope="platform")
        audit.record(db, "auth.login_failed", actor=user, resource_type="user", resource_id=user.id,
                     metadata={"reason": reason}, scope="platform")
        db.commit()
        raise HTTPException(status_code=401, detail=GENERIC_LOGIN_ERROR)
    if platform_settings.require_email_verification and user.email_verified_at is None:
        db.commit()
        raise HTTPException(status_code=403, detail="Verify your email address before signing in.")
    user.failed_login_count = 0
    user.locked_until = None
    if needs_rehash:
        user.password_hash = hash_password(body.password)
    session = _create_session(db, request, response, user, mfa_pending=user.mfa_enabled)
    if user.mfa_enabled:
        audit.record(db, "auth.mfa_challenge", actor=user, resource_type="user", resource_id=user.id, scope="platform")
        db.commit()
        return {"status": "mfa_required"}
    user.last_login_at = now
    audit.record(db, "auth.login", actor=user, resource_type="user", resource_id=user.id, scope="platform")
    db.commit()
    return {"status": "authenticated", **user_payload(db, user, session)}


@router.post("/mfa/verify")
def mfa_verify(body: CodeRequest, request: Request, response: Response,
               auth: AuthContext = Depends(current_auth_mfa_pending), db: Session = Depends(get_db)):
    if not auth.session.mfa_pending:
        raise HTTPException(status_code=400, detail="No multi-factor challenge is pending.")
    hit_rate_limit(f"mfa:{auth.user.id}", limit=8, window_seconds=600)
    user = auth.user
    counter = verify_totp(decrypt_secret(user.mfa_secret_enc), body.code, user.mfa_last_counter) if user.mfa_secret_enc else None
    if counter is None:
        audit.record(db, "auth.mfa_failed", actor=user, resource_type="user", resource_id=user.id, scope="platform")
        db.commit()
        raise HTTPException(status_code=401, detail="The verification code is incorrect.")
    user.mfa_last_counter = counter
    auth.session.revoked_at = utcnow()
    session = _create_session(db, request, response, user, mfa_pending=False)
    user.last_login_at = utcnow()
    audit.record(db, "auth.login", actor=user, resource_type="user", resource_id=user.id, metadata={"mfa": True}, scope="platform")
    db.commit()
    return {"status": "authenticated", **user_payload(db, user, session)}


@router.post("/logout")
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        session = db.execute(select(UserSession).where(UserSession.token_hash == token_digest(token))).scalar_one_or_none()
        if session and session.revoked_at is None:
            # Logout is CSRF-checked only when a live session exists.
            from ..deps import CSRF_HEADER
            from ..security import constant_time_equals

            supplied = request.headers.get(CSRF_HEADER, "")
            if not supplied or not constant_time_equals(supplied, session.csrf_token):
                raise HTTPException(status_code=403, detail="CSRF token missing or invalid.")
            session.revoked_at = utcnow()
            user = db.get(User, session.user_id)
            audit.record(db, "auth.logout", actor=user, resource_type="session", resource_id=session.id, scope="platform")
            db.commit()
    _clear_session_cookie(response)
    return {"status": "signed_out"}


@router.get("/session")
def session_info(auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)):
    return user_payload(db, auth.user, auth.session)


@router.patch("/me")
def update_profile(body: ProfileUpdate, auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)):
    auth.user.display_name = body.display_name
    db.commit()
    return user_payload(db, auth.user, auth.session)


@router.post("/me/active-organization")
def set_active_org(body: ActiveOrgRequest, auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)):
    member = db.execute(
        select(Membership.id).where(Membership.org_id == body.org_id, Membership.user_id == auth.user.id)
    ).first()
    if member is None:
        raise HTTPException(status_code=404, detail="Organization not found.")
    auth.session.active_org_id = body.org_id
    db.commit()
    return user_payload(db, auth.user, auth.session)


@router.post("/verify-email")
def verify_email(body: TokenRequest, db: Session = Depends(get_db)):
    user = _consume_one_time_token(db, body.token, "verify_email")
    user.email_verified_at = user.email_verified_at or utcnow()
    audit.record(db, "auth.email_verified", actor=user, resource_type="user", resource_id=user.id, scope="platform")
    db.commit()
    return {"status": "verified"}


@router.post("/verify-email/resend", status_code=202)
def resend_verification(body: EmailRequest, request: Request, db: Session = Depends(get_db)):
    hit_rate_limit(f"verify-resend:{client_ip(request)}", limit=5, window_seconds=3600)
    user = db.execute(select(User).where(User.email == normalise_email(body.email))).scalar_one_or_none()
    dev_link = None
    if user and user.is_active and user.email_verified_at is None:
        dev_link = _send_verification(db, user)
        db.commit()
    return {"status": "accepted", "development_verification_link": dev_link}


@router.post("/password/forgot", status_code=202)
def forgot_password(body: EmailRequest, request: Request, db: Session = Depends(get_db)):
    hit_rate_limit(f"forgot-ip:{client_ip(request)}", limit=5, window_seconds=3600)
    email = normalise_email(body.email)
    hit_rate_limit(f"forgot-id:{email}", limit=3, window_seconds=3600)
    user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    dev_link = None
    if user and user.is_active:
        token = _issue_one_time_token(db, user, "reset_password", timedelta(minutes=30))
        link = f"{platform_settings.public_app_url}/reset-password?token={token}"
        result = send_email(user.email, "Reset your SecurCode password",
                            f"Use this link within 30 minutes to choose a new password:\n{link}\n\n"
                            "If you did not request this, ignore this message.")
        if result.mode == "console" and not platform_settings.is_production:
            dev_link = link
        audit.record(db, "auth.password_reset_requested", actor=user, resource_type="user", resource_id=user.id, scope="platform")
        db.commit()
    # Same response whether or not the account exists.
    return {"status": "accepted", "development_reset_link": dev_link}


@router.post("/password/reset")
def reset_password(body: ResetRequest, request: Request, db: Session = Depends(get_db)):
    hit_rate_limit(f"reset:{client_ip(request)}", limit=10, window_seconds=3600)
    user = _consume_one_time_token(db, body.token, "reset_password")
    try:
        validate_password_policy(body.new_password, user.email)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from None
    user.password_hash = hash_password(body.new_password)
    user.password_changed_at = utcnow()
    user.failed_login_count = 0
    user.locked_until = None
    revoked = db.execute(
        update(UserSession).where(UserSession.user_id == user.id, UserSession.revoked_at.is_(None)).values(revoked_at=utcnow())
    ).rowcount
    audit.record(db, "auth.password_reset", actor=user, resource_type="user", resource_id=user.id,
                 metadata={"sessions_revoked": revoked}, scope="platform")
    db.commit()
    return {"status": "password_reset"}


@router.post("/password/change")
def change_password(body: PasswordChangeRequest, auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)):
    hit_rate_limit(f"pwchange:{auth.user.id}", limit=10, window_seconds=3600)
    valid, _ = verify_password(body.current_password, auth.user.password_hash)
    if not valid:
        raise HTTPException(status_code=400, detail="Current password is incorrect.")
    try:
        validate_password_policy(body.new_password, auth.user.email)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from None
    auth.user.password_hash = hash_password(body.new_password)
    auth.user.password_changed_at = utcnow()
    revoked = db.execute(
        update(UserSession)
        .where(UserSession.user_id == auth.user.id, UserSession.id != auth.session.id, UserSession.revoked_at.is_(None))
        .values(revoked_at=utcnow())
    ).rowcount
    audit.record(db, "auth.password_changed", actor=auth.user, resource_type="user", resource_id=auth.user.id,
                 metadata={"other_sessions_revoked": revoked}, scope="platform")
    db.commit()
    return {"status": "password_changed", "other_sessions_revoked": revoked}


@router.get("/sessions")
def list_sessions(auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)):
    now = utcnow()
    sessions = db.execute(
        select(UserSession)
        .where(UserSession.user_id == auth.user.id, UserSession.revoked_at.is_(None), UserSession.expires_at > now,
               UserSession.mfa_pending.is_(False))
        .order_by(UserSession.last_seen_at.desc())
    ).scalars()
    return {
        "items": [
            {
                "id": s.id,
                "created_at": s.created_at.isoformat(),
                "last_seen_at": s.last_seen_at.isoformat(),
                "expires_at": s.expires_at.isoformat(),
                "ip_address": s.ip_address,
                "user_agent": s.user_agent,
                "current": s.id == auth.session.id,
            }
            for s in sessions
        ]
    }


@router.delete("/sessions/{session_id}")
def revoke_session(session_id: str, response: Response, auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)):
    session = db.execute(
        select(UserSession).where(UserSession.id == session_id, UserSession.user_id == auth.user.id)
    ).scalar_one_or_none()
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found.")
    session.revoked_at = session.revoked_at or utcnow()
    audit.record(db, "auth.session_revoked", actor=auth.user, resource_type="session", resource_id=session.id, scope="platform")
    db.commit()
    if session.id == auth.session.id:
        _clear_session_cookie(response)
    return {"status": "revoked"}


@router.post("/sessions/revoke-others")
def revoke_other_sessions(auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)):
    count = db.execute(
        update(UserSession)
        .where(UserSession.user_id == auth.user.id, UserSession.id != auth.session.id, UserSession.revoked_at.is_(None))
        .values(revoked_at=utcnow())
    ).rowcount
    audit.record(db, "auth.session_revoked", actor=auth.user, resource_type="user", resource_id=auth.user.id,
                 metadata={"count": count, "scope": "others"}, scope="platform")
    db.commit()
    return {"status": "revoked", "count": count}


@router.post("/mfa/setup")
def mfa_setup(auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)):
    if auth.user.mfa_enabled:
        raise HTTPException(status_code=409, detail="Multi-factor authentication is already enabled.")
    secret = new_totp_secret()
    auth.user.mfa_secret_enc = encrypt_secret(secret)
    auth.user.mfa_last_counter = None
    db.commit()
    # The secret is shown once so it can be added to an authenticator app.
    return {"secret": secret, "otpauth_uri": totp_uri(secret, auth.user.email)}


@router.post("/mfa/enable")
def mfa_enable(body: CodeRequest, auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)):
    if auth.user.mfa_enabled or not auth.user.mfa_secret_enc:
        raise HTTPException(status_code=400, detail="Start MFA setup first.")
    hit_rate_limit(f"mfa-enable:{auth.user.id}", limit=8, window_seconds=600)
    counter = verify_totp(decrypt_secret(auth.user.mfa_secret_enc), body.code, None)
    if counter is None:
        raise HTTPException(status_code=400, detail="The verification code is incorrect.")
    auth.user.mfa_enabled = True
    auth.user.mfa_last_counter = counter
    audit.record(db, "auth.mfa_enabled", actor=auth.user, resource_type="user", resource_id=auth.user.id, scope="platform")
    db.commit()
    return {"status": "enabled"}


@router.post("/mfa/disable")
def mfa_disable(body: MfaDisableRequest, auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)):
    hit_rate_limit(f"mfa-disable:{auth.user.id}", limit=8, window_seconds=600)
    valid, _ = verify_password(body.password, auth.user.password_hash)
    counter = (
        verify_totp(decrypt_secret(auth.user.mfa_secret_enc), body.code, auth.user.mfa_last_counter)
        if auth.user.mfa_enabled and auth.user.mfa_secret_enc else None
    )
    if not valid or counter is None:
        raise HTTPException(status_code=400, detail="Password or verification code is incorrect.")
    auth.user.mfa_enabled = False
    auth.user.mfa_secret_enc = None
    auth.user.mfa_last_counter = None
    audit.record(db, "auth.mfa_disabled", actor=auth.user, resource_type="user", resource_id=auth.user.id, scope="platform")
    db.commit()
    return {"status": "disabled"}
