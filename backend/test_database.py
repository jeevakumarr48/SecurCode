import sqlite3
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend import database  # noqa: E402


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


def test_sqlite_online_backup_restores_data_and_schema(tmp_path, monkeypatch):
    source_path = tmp_path / "source.sqlite"
    backup_path = tmp_path / "backup.sqlite"
    restored_path = tmp_path / "restored.sqlite"
    monkeypatch.setattr(database, "DATABASE_PATH", source_path)
    database.initialize_database()
    database.save_scan(
        "backend/security_engine",
        {"status": "completed", "total_findings": 0, "findings": []},
    )

    with database.get_connection() as source, sqlite3.connect(backup_path) as backup:
        source.backup(backup)

    with sqlite3.connect(backup_path) as backup, sqlite3.connect(restored_path) as restored:
        backup.backup(restored)

    with sqlite3.connect(restored_path) as restored:
        assert restored.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert restored.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 1
        assert {row[0] for row in restored.execute("SELECT version FROM schema_migrations")} >= set(range(1, 8))
