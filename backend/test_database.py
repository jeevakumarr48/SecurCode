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
