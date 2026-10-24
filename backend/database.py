
import json
import sqlite3
from pathlib import Path

DATABASE_PATH = Path(__file__).resolve().parent / "sentinelops.db"


def get_connection():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    with get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_path TEXT NOT NULL,
                status TEXT NOT NULL,
                total_findings INTEGER NOT NULL,
                findings_json TEXT NOT NULL,
                errors_json TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL DEFAULT (
                    strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                )
            )
        """)
        columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(scans)")
        }
        if "errors_json" not in columns:
            connection.execute(
                "ALTER TABLE scans ADD COLUMN errors_json TEXT NOT NULL DEFAULT '[]'"
            )


def save_scan(project_path, result):
    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO scans (
                project_path, status, total_findings, findings_json, errors_json
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                project_path,
                result["status"],
                result["total_findings"],
                json.dumps(result["findings"]),
                json.dumps(result.get("errors", [])),
            ),
        )
        return cursor.lastrowid


def get_scan_history(limit=20):
    limit = max(1, min(int(limit), 100))

    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT * FROM scans
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    history = []

    for row in rows:
        item = dict(row)
        item["findings"] = json.loads(item.pop("findings_json"))
        item["errors"] = json.loads(item.pop("errors_json"))
        history.append(item)

    return history


def get_scan_statistics():
    with get_connection() as connection:
        summary = connection.execute("""
            SELECT
                COUNT(*) AS total_scans,
                COALESCE(SUM(total_findings), 0) AS total_findings
            FROM scans
        """).fetchone()

        latest = connection.execute("""
            SELECT id, project_path, status, total_findings, created_at
            FROM scans
            ORDER BY id DESC
            LIMIT 1
        """).fetchone()

        rows = connection.execute(
            "SELECT findings_json FROM scans"
        ).fetchall()

    high_severity = 0

    for row in rows:
        findings = json.loads(row["findings_json"])

        for finding in findings:
            if finding.get("severity") in {"HIGH", "CRITICAL"}:
                high_severity += 1

    return {
        "total_scans": summary["total_scans"],
        "total_findings": summary["total_findings"],
        "high_severity_findings": high_severity,
        "latest_scan": dict(latest) if latest else None,
    }
