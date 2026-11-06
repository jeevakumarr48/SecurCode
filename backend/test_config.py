import os
from pathlib import Path
import subprocess
import sys

import pytest

from config import load_settings, validate_bootstrap_configuration


def test_production_requires_restricted_demo_and_exact_https_origins(monkeypatch, tmp_path):
    monkeypatch.setenv("SECURCODE_ENV", "production")
    monkeypatch.setenv("SECURCODE_DEMO_MODE", "true")
    monkeypatch.setenv("SECURCODE_ALLOWED_ORIGINS", "https://console.example/")
    settings = load_settings()
    assert settings.allowed_origins == ("https://console.example",)
    assert settings.demo_mode is True

    monkeypatch.setenv("SECURCODE_ALLOWED_ORIGINS", "https://console.example:443")
    assert load_settings().allowed_origins == ("https://console.example",)

    monkeypatch.setenv("SECURCODE_DEMO_MODE", "false")
    monkeypatch.delenv("SECURCODE_BOOTSTRAP_TOKEN", raising=False)
    monkeypatch.setenv("SECURCODE_DATABASE_PATH", str(tmp_path / "production.sqlite"))
    settings = load_settings()
    assert settings.demo_mode is False
    with pytest.raises(RuntimeError, match="no accounts requires"):
        validate_bootstrap_configuration(0, settings)
    validate_bootstrap_configuration(1, settings)

    monkeypatch.setenv("SECURCODE_BOOTSTRAP_TOKEN", "too-short")
    with pytest.raises(RuntimeError, match="at least 32 characters"):
        load_settings()


def test_production_can_start_without_bootstrap_secret_after_accounts_exist(monkeypatch, tmp_path):
    monkeypatch.setenv("SECURCODE_ENV", "production")
    monkeypatch.setenv("SECURCODE_DEMO_MODE", "false")
    monkeypatch.setenv("SECURCODE_ALLOWED_ORIGINS", "https://console.example")
    monkeypatch.setenv("SECURCODE_DATABASE_PATH", str(tmp_path / "production.sqlite"))
    monkeypatch.delenv("SECURCODE_BOOTSTRAP_TOKEN", raising=False)

    settings = load_settings()
    validate_bootstrap_configuration(1, settings)
    with pytest.raises(RuntimeError, match="no accounts requires"):
        validate_bootstrap_configuration(0, settings)


def test_production_application_disables_public_api_documentation(tmp_path):
    environment = os.environ.copy()
    environment.update({
        "SECURCODE_ENV": "production",
        "SECURCODE_DEMO_MODE": "false",
        "SECURCODE_ALLOWED_ORIGINS": "https://console.example",
        "SECURCODE_DATABASE_PATH": str(tmp_path / "isolated-production.sqlite"),
        "SECURCODE_BOOTSTRAP_TOKEN": "test-only-bootstrap-token-at-least-32-chars",
    })
    backend_dir = Path(__file__).resolve().parent
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from app.main import app; "
            "assert app.docs_url is None; "
            "assert app.redoc_url is None; "
            "assert app.openapi_url is None",
        ],
        cwd=backend_dir,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr


def test_private_production_requires_absolute_database_path(monkeypatch, tmp_path):
    monkeypatch.setenv("SECURCODE_ENV", "production")
    monkeypatch.setenv("SECURCODE_DEMO_MODE", "false")
    monkeypatch.setenv("SECURCODE_ALLOWED_ORIGINS", "https://console.example")
    monkeypatch.setenv("SECURCODE_BOOTSTRAP_TOKEN", "a-long-random-production-bootstrap-token")
    monkeypatch.delenv("SECURCODE_DATABASE_PATH", raising=False)
    with pytest.raises(RuntimeError, match="absolute SECURCODE_DATABASE_PATH"):
        load_settings()

    monkeypatch.setenv("SECURCODE_DATABASE_PATH", "relative.sqlite")
    with pytest.raises(RuntimeError, match="absolute SECURCODE_DATABASE_PATH"):
        load_settings()

    monkeypatch.setenv("SECURCODE_DATABASE_PATH", str(tmp_path / "production.sqlite"))
    assert load_settings().database_path == tmp_path / "production.sqlite"
    monkeypatch.setenv("SECURCODE_DATABASE_PATH", str(tmp_path / "missing" / "production.sqlite"))
    with pytest.raises(RuntimeError, match="existing mounted directory"):
        load_settings()


@pytest.mark.parametrize("origin", ["https://console.example/path", "https://console.example?x=1", "https://console.example?", "https://console.example#", "https://user@console.example"])
def test_origin_parser_rejects_non_origin_components(monkeypatch, origin):
    monkeypatch.setenv("SECURCODE_ENV", "development")
    monkeypatch.setenv("SECURCODE_ALLOWED_ORIGINS", origin)
    with pytest.raises(RuntimeError, match="exact web origins"):
        load_settings()


def test_origin_parser_rejects_invalid_port(monkeypatch):
    monkeypatch.setenv("SECURCODE_ENV", "development")
    monkeypatch.setenv("SECURCODE_ALLOWED_ORIGINS", "https://console.example:not-a-port")
    with pytest.raises(RuntimeError, match="invalid port"):
        load_settings()


def test_production_rejects_http_origin(monkeypatch):
    monkeypatch.setenv("SECURCODE_ENV", "production")
    monkeypatch.setenv("SECURCODE_DEMO_MODE", "true")
    monkeypatch.setenv("SECURCODE_ALLOWED_ORIGINS", "http://console.example")
    with pytest.raises(RuntimeError, match="HTTPS"):
        load_settings()


def test_database_and_scan_limits_are_configurable_and_bounded(monkeypatch, tmp_path):
    monkeypatch.setenv("SECURCODE_ENV", "development")
    monkeypatch.setenv("SECURCODE_DATABASE_PATH", str(tmp_path / "securcode.sqlite"))
    monkeypatch.setenv("SECURCODE_MAX_SCAN_FILES", "25")
    monkeypatch.setenv("SECURCODE_MAX_SCAN_DEPTH", "12")
    monkeypatch.setenv("SECURCODE_MAX_SCAN_SECONDS", "45")
    monkeypatch.setenv("SECURCODE_MAX_SOURCE_FILE_BYTES", "250000")
    monkeypatch.setenv("SECURCODE_MAX_SCAN_BYTES", "1000000")
    settings = load_settings()
    assert settings.database_path == tmp_path / "securcode.sqlite"
    assert settings.max_scan_files == 25
    assert settings.max_scan_depth == 12
    assert settings.max_scan_seconds == 45
    assert settings.max_source_file_bytes == 250000
    assert settings.max_scan_bytes == 1000000

    monkeypatch.setenv("SECURCODE_MAX_SCAN_FILES", "0")
    with pytest.raises(RuntimeError, match="between"):
        load_settings()

    monkeypatch.setenv("SECURCODE_MAX_SCAN_DEPTH", "257")
    with pytest.raises(RuntimeError, match="between"):
        load_settings()
