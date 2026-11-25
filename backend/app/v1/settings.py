"""Configuration for the multi-tenant /api/v1 platform.

All values come from environment variables. Nothing secret has a default
that is usable in production: startup fails closed instead.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from config import settings as legacy_settings


def _bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    value = raw.strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise RuntimeError(f"{name} must be a boolean value.")


def _int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.getenv(name)
    try:
        value = default if raw is None or raw.strip() == "" else int(raw)
    except ValueError as error:
        raise RuntimeError(f"{name} must be an integer.") from error
    if not minimum <= value <= maximum:
        raise RuntimeError(f"{name} must be between {minimum} and {maximum}.")
    return value


def _development_key() -> str:
    """Create a local, gitignored Fernet key for development only."""
    from cryptography.fernet import Fernet

    path = Path(__file__).resolve().parents[2] / ".securcode-dev.key"
    try:
        if path.exists():
            return path.read_text(encoding="ascii").strip()
        key = Fernet.generate_key().decode("ascii")
        path.write_text(key, encoding="ascii")
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return key
    except OSError:
        return Fernet.generate_key().decode("ascii")


def _database_url() -> str:
    url = os.getenv("SECURCODE_DATABASE_URL", "").strip()
    if url:
        # Render and Heroku style URLs use the deprecated postgres:// scheme.
        if url.startswith("postgres://"):
            url = "postgresql+psycopg://" + url[len("postgres://"):]
        elif url.startswith("postgresql://"):
            url = "postgresql+psycopg://" + url[len("postgresql://"):]
        return url
    return f"sqlite:///{Path(legacy_settings.database_path).as_posix()}"


@dataclass(frozen=True)
class PlatformSettings:
    environment: str
    database_url: str
    public_app_url: str
    cookie_secure: bool
    cookie_samesite: str
    cookie_domain: str | None
    session_hours: int
    session_idle_minutes: int
    encryption_key: str | None
    registration_open: bool
    require_email_verification: bool
    max_upload_bytes: int
    max_archive_members: int
    max_extracted_bytes: int
    scan_timeout_seconds: int
    scan_memory_mb: int
    worker_concurrency: int
    login_max_failures: int
    lockout_minutes: int
    smtp_host: str | None
    smtp_port: int
    smtp_username: str | None
    smtp_password: str | None = field(repr=False, default=None)
    smtp_from: str = "SecurCode <no-reply@localhost>"
    smtp_starttls: bool = True
    github_api_url: str = "https://api.github.com"
    ai_provider_url: str | None = None

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")

    @property
    def email_configured(self) -> bool:
        return bool(self.smtp_host)


def load_platform_settings() -> PlatformSettings:
    environment = legacy_settings.environment
    production = environment == "production"
    samesite = os.getenv("SECURCODE_COOKIE_SAMESITE", "lax").strip().lower()
    if samesite not in {"lax", "strict"}:
        # Cross-site cookies (SameSite=None) are intentionally unsupported: the
        # console reaches /api/v1 on its own origin.
        raise RuntimeError("SECURCODE_COOKIE_SAMESITE must be lax or strict.")
    cookie_secure = _bool("SECURCODE_COOKIE_SECURE", production)
    if production and not cookie_secure:
        raise RuntimeError("Production requires SECURCODE_COOKIE_SECURE=true.")

    encryption_key = os.getenv("SECURCODE_ENCRYPTION_KEY") or None
    if not encryption_key and environment == "development":
        encryption_key = _development_key()
    if production and not encryption_key:
        raise RuntimeError(
            "Production requires SECURCODE_ENCRYPTION_KEY (a Fernet key) for stored integration credentials."
        )

    database_url = _database_url()
    if production and database_url.startswith("sqlite") and not _bool("SECURCODE_ALLOW_SQLITE_IN_PRODUCTION", False):
        raise RuntimeError(
            "Production requires SECURCODE_DATABASE_URL pointing at PostgreSQL "
            "(set SECURCODE_ALLOW_SQLITE_IN_PRODUCTION=true only for single-host durable disks)."
        )

    github_api_url = os.getenv("SECURCODE_GITHUB_API_URL", "https://api.github.com").rstrip("/")
    if not github_api_url.startswith("https://"):
        raise RuntimeError("SECURCODE_GITHUB_API_URL must use HTTPS.")

    return PlatformSettings(
        environment=environment,
        database_url=database_url,
        public_app_url=os.getenv("SECURCODE_PUBLIC_APP_URL", "http://localhost:5173").rstrip("/"),
        cookie_secure=cookie_secure,
        cookie_samesite=samesite,
        cookie_domain=os.getenv("SECURCODE_COOKIE_DOMAIN") or None,
        session_hours=_int("SECURCODE_SESSION_HOURS", 12, 1, 24 * 30),
        session_idle_minutes=_int("SECURCODE_SESSION_IDLE_MINUTES", 120, 5, 24 * 60),
        encryption_key=encryption_key,
        registration_open=_bool("SECURCODE_REGISTRATION_OPEN", True),
        require_email_verification=_bool("SECURCODE_REQUIRE_EMAIL_VERIFICATION", False),
        max_upload_bytes=_int("SECURCODE_MAX_UPLOAD_BYTES", 25_000_000, 1024, 200_000_000),
        max_archive_members=_int("SECURCODE_MAX_ARCHIVE_MEMBERS", 20_000, 1, 200_000),
        max_extracted_bytes=_int("SECURCODE_MAX_EXTRACTED_BYTES", 200_000_000, 1024, 2_000_000_000),
        scan_timeout_seconds=_int("SECURCODE_SCAN_TIMEOUT_SECONDS", 300, 5, 3600),
        scan_memory_mb=_int("SECURCODE_SCAN_MEMORY_MB", 1024, 128, 16384),
        worker_concurrency=_int("SECURCODE_WORKER_CONCURRENCY", 2, 1, 32),
        login_max_failures=_int("SECURCODE_LOGIN_MAX_FAILURES", 8, 3, 100),
        lockout_minutes=_int("SECURCODE_LOCKOUT_MINUTES", 15, 1, 24 * 60),
        smtp_host=os.getenv("SECURCODE_SMTP_HOST") or None,
        smtp_port=_int("SECURCODE_SMTP_PORT", 587, 1, 65535),
        smtp_username=os.getenv("SECURCODE_SMTP_USERNAME") or None,
        smtp_password=os.getenv("SECURCODE_SMTP_PASSWORD") or None,
        smtp_from=os.getenv("SECURCODE_SMTP_FROM", "SecurCode <no-reply@localhost>"),
        smtp_starttls=_bool("SECURCODE_SMTP_STARTTLS", True),
        github_api_url=github_api_url,
        ai_provider_url=os.getenv("SECURCODE_AI_PROVIDER_URL") or None,
    )


platform_settings = load_platform_settings()
