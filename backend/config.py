"""Validated, lightweight application configuration."""

from dataclasses import dataclass
import os
from pathlib import Path
from urllib.parse import urlsplit


def _boolean(name, default=False):
    value = os.getenv(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off", ""}:
        return False
    raise RuntimeError(f"{name} must be a boolean value.")


def _integer(name, default, minimum, maximum):
    raw = os.getenv(name)
    try:
        value = default if raw is None else int(raw)
    except ValueError as error:
        raise RuntimeError(f"{name} must be an integer.") from error
    if not minimum <= value <= maximum:
        raise RuntimeError(f"{name} must be between {minimum} and {maximum}.")
    return value


def parse_allowed_origins():
    values = [item.strip() for item in os.getenv("SECURCODE_ALLOWED_ORIGINS", "").split(",") if item.strip()]
    normalized = []
    for value in values:
        parsed = urlsplit(value)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or "?" in value
            or "#" in value
        ):
            raise RuntimeError("SECURCODE_ALLOWED_ORIGINS must contain exact web origins.")
        try:
            port = parsed.port
        except ValueError as error:
            raise RuntimeError("SECURCODE_ALLOWED_ORIGINS contains an invalid port.") from error
        host = (parsed.hostname or "").lower()
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        is_default_port = (parsed.scheme == "http" and port == 80) or (parsed.scheme == "https" and port == 443)
        authority = f"{host}:{port}" if port is not None and not is_default_port else host
        normalized.append(f"{parsed.scheme.lower()}://{authority}")
    if len(normalized) != len(set(normalized)):
        normalized = list(dict.fromkeys(normalized))
    return tuple(normalized)


@dataclass(frozen=True)
class Settings:
    environment: str
    demo_mode: bool
    allowed_origins: tuple[str, ...]
    demo_scan_cooldown_seconds: int
    database_path: Path
    max_scan_files: int
    max_scan_depth: int
    max_scan_seconds: int
    max_source_file_bytes: int
    max_scan_bytes: int


def load_settings():
    environment = os.getenv("SECURCODE_ENV", "development").strip().lower()
    if environment not in {"development", "test", "production"}:
        raise RuntimeError("SECURCODE_ENV must be development, test, or production.")
    configured_origins = parse_allowed_origins()
    demo_mode = _boolean("SECURCODE_DEMO_MODE")
    if environment == "production":
        if not configured_origins or any(not origin.startswith("https://") for origin in configured_origins):
            raise RuntimeError("Production requires explicit HTTPS SECURCODE_ALLOWED_ORIGINS.")
        bootstrap_token = os.getenv("SECURCODE_BOOTSTRAP_TOKEN", "")
        if not demo_mode and bootstrap_token and len(bootstrap_token) < 32:
            raise RuntimeError("SECURCODE_BOOTSTRAP_TOKEN must contain at least 32 characters when configured.")

    default_database = Path(__file__).resolve().parent / "sentinelops.db"
    configured_database_path = os.getenv("SECURCODE_DATABASE_PATH")
    database_path = Path(configured_database_path if configured_database_path and configured_database_path.strip() else default_database).expanduser()
    if environment == "production" and not demo_mode and (
        not configured_database_path
        or not configured_database_path.strip()
        or not Path(configured_database_path).expanduser().is_absolute()
    ):
        raise RuntimeError(
            "Private production requires an absolute SECURCODE_DATABASE_PATH on durable mounted storage."
        )
    if not database_path.is_absolute():
        database_path = (Path.cwd() / database_path).resolve()
    if environment == "production" and not demo_mode and not database_path.parent.is_dir():
        raise RuntimeError(
            "Private production SECURCODE_DATABASE_PATH parent must be an existing mounted directory."
        )

    return Settings(
        environment=environment,
        demo_mode=demo_mode,
        allowed_origins=configured_origins,
        demo_scan_cooldown_seconds=_integer("SECURCODE_DEMO_SCAN_COOLDOWN_SECONDS", 10, 1, 3600),
        database_path=database_path,
        max_scan_files=_integer("SECURCODE_MAX_SCAN_FILES", 5000, 1, 50000),
        max_scan_depth=_integer("SECURCODE_MAX_SCAN_DEPTH", 30, 1, 256),
        max_scan_seconds=_integer("SECURCODE_MAX_SCAN_SECONDS", 120, 1, 3600),
        max_source_file_bytes=_integer("SECURCODE_MAX_SOURCE_FILE_BYTES", 2_000_000, 1024, 20_000_000),
        max_scan_bytes=_integer("SECURCODE_MAX_SCAN_BYTES", 100_000_000, 1024, 1_000_000_000),
    )


def validate_bootstrap_configuration(user_count, configuration=None):
    """Require a bootstrap secret only while a private production DB has no users."""
    configuration = settings if configuration is None else configuration
    if (
        configuration.environment == "production"
        and not configuration.demo_mode
        and user_count == 0
        and len(os.getenv("SECURCODE_BOOTSTRAP_TOKEN", "")) < 32
    ):
        raise RuntimeError(
            "Private production with no accounts requires a SECURCODE_BOOTSTRAP_TOKEN of at least 32 characters."
        )


settings = load_settings()
