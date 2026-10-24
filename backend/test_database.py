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
