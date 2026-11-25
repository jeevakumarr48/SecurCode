import json
import os
import sqlite3
from pathlib import Path
import subprocess
import sys

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend import database  # noqa: E402
from scripts.sqlite_backup_restore import backup_database, restore_database  # noqa: E402


def test_scan_history_and_statistics_persist_language_findings(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "test.db")
    database.initialize_database()
    database.save_scan(
        "project",
        {
            "status": "completed",
            "total_findings": 2,
            "findings": [
                {
                    "severity": "HIGH",
                    "confidence": "HIGH",
                    "test_id": "PYSEC003",
                    "language": "Python",
                    "filename": "project/app.py",
                    "line_number": 4,
                    "description": "Unsafe deserialization detected.",
                },
                {
                    "severity": "MEDIUM",
                    "confidence": "MEDIUM",
                    "test_id": "JSSEC005",
                    "language": "JavaScript",
                    "filename": "project/app.js",
                    "line_number": 2,
                    "description": "Hardcoded credential-like value detected.",
                },
            ],
        },
    )
    database.initialize_database()

    history = database.get_scan_history()
    statistics = database.get_scan_statistics()

    assert history[0]["findings"][0]["language"] == "Python"
    assert statistics["total_scans"] == 1
    assert statistics["total_findings"] == 2
    assert statistics["high_severity_findings"] == 1


def test_partial_scan_errors_are_persisted_in_history(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "test.db")
    database.initialize_database()

    database.save_scan(
        "project",
        {
            "status": "partial",
            "total_findings": 0,
            "findings": [],
            "errors": [{
                "path": "project/invalid.py",
                "message": "Source file scan failed (SyntaxError).",
            }],
        },
    )

    history = database.get_scan_history()

    assert history[0]["status"] == "partial"
    assert history[0]["errors"][0]["message"] == (
        "Source file scan failed (SyntaxError)."
    )


def test_initialize_database_migrates_existing_scan_history(tmp_path, monkeypatch):
    database_path = tmp_path / "existing.db"
    monkeypatch.setattr(database, "DATABASE_PATH", database_path)
    with sqlite3.connect(database_path) as connection:
        connection.execute("""
            CREATE TABLE scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_path TEXT NOT NULL,
                status TEXT NOT NULL,
                total_findings INTEGER NOT NULL,
                findings_json TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (
                    strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                )
            )
        """)

    database.initialize_database()
    database.save_scan(
        "project",
        {"status": "failed", "total_findings": 0, "findings": []},
    )

    history = database.get_scan_history()

    assert history[0]["status"] == "failed"
    assert history[0]["errors"] == []


def test_audit_hash_chain_detects_metadata_tampering(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "audit.db")
    database.initialize_database()
    with database.get_connection() as connection:
        database.record_audit_event(connection, "analyst", "finding.updated", "finding", "12:0", {"status": "Resolved"})
        database.record_audit_event(connection, "analyst", "report.generated", "report", "summary", {})
        assert database.verify_audit_chain(connection)["valid"] is True
        connection.execute("UPDATE audit_events SET metadata_json = '{}' WHERE id = 1")
        result = database.verify_audit_chain(connection)

    assert result == {"valid": False, "event_id": 1}


def test_audit_writer_redacts_nested_credentials_before_persisting(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "audit-secrets.db")
    database.initialize_database()
    secrets = {
        "password": "plain-password-value",
        "nested": {
            "password_hash": "password-hash-value",
            "password_salt": "password-salt-value",
            "access_token": "access-token-value",
            "bootstrap_token": "bootstrap-token-value",
            "session_secret": "session-secret-value",
            "authorization": "authorization-value",
            "safe": "retained",
        },
    }

    with database.get_connection() as connection:
        database.record_audit_event(
            connection, "admin", "auth.user_updated", "user", 2, secrets
        )
        stored = connection.execute(
            "SELECT metadata_json FROM audit_events"
        ).fetchone()["metadata_json"]
        assert database.verify_audit_chain(connection)["valid"] is True

    assert "plain-password-value" not in stored
    assert "password-hash-value" not in stored
    assert "password-salt-value" not in stored
    assert "access-token-value" not in stored
    assert "bootstrap-token-value" not in stored
    assert "session-secret-value" not in stored
    assert "authorization-value" not in stored
    assert '"safe":"retained"' in stored


def test_initialize_database_redacts_legacy_audit_secrets_and_rechains(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "legacy-audit.db")
    database.initialize_database()
    with database.get_connection() as connection:
        connection.execute("DELETE FROM schema_migrations WHERE version = 6")
        connection.execute(
            """INSERT INTO audit_events(
                actor, action, resource_type, resource_id, metadata_json
            ) VALUES (?, ?, ?, ?, ?)""",
            (
                "admin",
                "auth.user_updated",
                "user",
                "2",
                '{"password_hash":"legacy-hash","password_salt":"legacy-salt"}',
            ),
        )

    database.initialize_database()

    with database.get_connection() as connection:
        stored = connection.execute(
            "SELECT metadata_json FROM audit_events"
        ).fetchone()["metadata_json"]
        assert database.verify_audit_chain(connection)["valid"] is True

    assert "legacy-hash" not in stored
    assert "legacy-salt" not in stored
    assert '"password_hash":"[REDACTED]"' in stored


def test_audit_hash_chain_additive_migration_is_idempotent(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "audit.db")
    database.initialize_database()
    with database.get_connection() as connection:
        versions = {row[0] for row in connection.execute("SELECT version FROM schema_migrations")}
        audit_columns = {row["name"] for row in connection.execute("PRAGMA table_info(audit_events)")}

    database.initialize_database()
    assert {1, 2, 3, 4, 5, 6, 7}.issubset(versions)
    assert {"previous_hash", "event_hash"}.issubset(audit_columns)


def test_configured_database_path_preserves_data_across_restarts(tmp_path):
    database_path = tmp_path / "mounted" / "configured.sqlite"
    database_path.parent.mkdir()
    with sqlite3.connect(database_path) as connection:
        connection.execute("CREATE TABLE preexisting_data (value TEXT NOT NULL)")
        connection.execute("INSERT INTO preexisting_data VALUES ('preserve-me')")

    environment = os.environ.copy()
    environment.update({
        "SECURCODE_ENV": "test",
        "SECURCODE_DEMO_MODE": "false",
        "SECURCODE_ALLOWED_ORIGINS": "",
        "SECURCODE_DATABASE_PATH": str(database_path),
    })
    setup_code = """
from pathlib import Path
import os
from config import settings
from database import get_connection, initialize_database, save_scan
assert settings.database_path == Path(os.environ["SECURCODE_DATABASE_PATH"])
initialize_database()
save_scan("project", {
    "status": "completed",
    "total_findings": 1,
    "findings": [{"severity": "HIGH", "test_id": "fixture", "filename": "app.py", "line_number": 1}],
})
with get_connection() as connection:
    connection.execute(
        "INSERT INTO auth_users(username, password_salt, password_hash, role) VALUES (?, ?, ?, ?)",
        ("release-admin", "test-salt-fixture", "test-hash-fixture", "administrator"),
    )
    connection.execute(
        "UPDATE finding_states SET status = 'In Progress', assignee = 'analyst' WHERE scan_id = 1"
    )
"""
    restart_code = """
from database import get_connection, initialize_database
initialize_database()
with get_connection() as connection:
    assert connection.execute("SELECT value FROM preexisting_data").fetchone()[0] == "preserve-me"
    assert connection.execute("SELECT role FROM auth_users WHERE username = 'release-admin'").fetchone()[0] == "administrator"
    assert connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 1
    state = connection.execute("SELECT status, assignee FROM finding_states WHERE scan_id = 1").fetchone()
    assert tuple(state) == ("In Progress", "analyst")
"""
    for code in (setup_code, restart_code):
        result = subprocess.run(
            [sys.executable, "-c", code],
            cwd=PROJECT_ROOT / "backend",
            env=environment,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        assert result.returncode == 0, result.stderr


def test_connections_enable_foreign_keys_and_rollback_on_error(tmp_path, monkeypatch):
    database_path = tmp_path / "connections.sqlite"
    monkeypatch.setattr(database, "DATABASE_PATH", database_path)
    database.initialize_database()

    with pytest.raises(RuntimeError, match="rollback fixture"):
        with database.get_connection() as connection:
            assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
            assert connection.execute("PRAGMA busy_timeout").fetchone()[0] == 10000
            assert connection.execute("PRAGMA journal_mode").fetchone()[0].lower() == "delete"
            connection.execute(
                "INSERT INTO projects(name, project_path) VALUES ('temporary', 'temporary')"
            )
            raise RuntimeError("rollback fixture")

    with sqlite3.connect(database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM projects").fetchone()[0] == 0

    with pytest.raises(sqlite3.IntegrityError):
        with database.get_connection() as connection:
            connection.execute(
                "INSERT INTO auth_sessions(user_id, token_hash, expires_at) VALUES (999, 'fixture', '2099-01-01')"
            )


def test_sqlite_online_backup_restores_accounts_findings_and_assignments(
    tmp_path, monkeypatch
):
    source_path = tmp_path / "source.sqlite"
    backup_path = tmp_path / "backup.sqlite"
    restored_path = tmp_path / "restored.sqlite"
    monkeypatch.setattr(database, "DATABASE_PATH", source_path)
    database.initialize_database()
    database.save_scan("project", {
        "status": "completed",
        "total_findings": 1,
        "findings": [{
            "severity": "HIGH",
            "test_id": "fixture",
            "filename": "app.py",
            "line_number": 1,
            "description": "Fixture finding.",
        }],
    })
    with database.get_connection() as connection:
        connection.execute(
            "INSERT INTO auth_users(username, password_salt, password_hash, role) VALUES (?, ?, ?, ?)",
            ("release-admin", "test-salt-fixture", "test-hash-fixture", "administrator"),
        )
        connection.execute(
            "UPDATE finding_states SET status = 'In Progress', assignee = 'analyst' WHERE scan_id = 1"
        )
        connection.execute(
            """INSERT INTO finding_status_history(
                scan_id, finding_index, from_status, to_status, actor, note
            ) VALUES (1, 0, 'Open', 'In Progress', 'administrator', 'Assigned for review')"""
        )

    backup_database(source_path, backup_path)
    restore_database(backup_path, restored_path)

    with sqlite3.connect(restored_path) as restored:
        assert restored.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert restored.execute("PRAGMA foreign_key_check").fetchall() == []
        assert restored.execute(
            "SELECT username, role FROM auth_users"
        ).fetchone() == ("release-admin", "administrator")
        scan = restored.execute(
            "SELECT status, total_findings, findings_json FROM scans"
        ).fetchone()
        assert scan[:2] == ("completed", 1)
        assert json.loads(scan[2])[0]["test_id"] == "fixture"
        finding_state = restored.execute(
            "SELECT status, assignee FROM finding_states WHERE scan_id = 1"
        ).fetchone()
        assert finding_state == ("In Progress", "analyst")
        assert restored.execute(
            "SELECT COUNT(*) FROM finding_status_history"
        ).fetchone()[0] == 1
        assert {row[0] for row in restored.execute("SELECT version FROM schema_migrations")} >= set(range(1, 8))


def test_backup_and_restore_refuse_existing_destinations(tmp_path, monkeypatch):
    source_path = tmp_path / "source.sqlite"
    backup_path = tmp_path / "backup.sqlite"
    existing_path = tmp_path / "existing.sqlite"
    monkeypatch.setattr(database, "DATABASE_PATH", source_path)
    database.initialize_database()
    backup_database(source_path, backup_path)
    existing_path.write_bytes(b"existing destination")

    with pytest.raises(FileExistsError):
        restore_database(backup_path, existing_path)

    assert existing_path.read_bytes() == b"existing destination"
