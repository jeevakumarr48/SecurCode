from pathlib import Path
import sys

import pytest
from fastapi import HTTPException

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.api import routes  # noqa: E402
from backend.app import main as app_main  # noqa: E402


def test_status_uses_securcode_service_name():
    assert routes.status()["service"] == "SecurCode Security Scanner"


def test_scan_rejects_absolute_and_traversal_paths():
    with pytest.raises(HTTPException) as absolute_error:
        routes.scan(routes.ScanRequest(project_path=str(Path.cwd())))
    with pytest.raises(HTTPException) as traversal_error:
        routes.scan(routes.ScanRequest(project_path="../outside"))

    assert absolute_error.value.status_code == 400
    assert traversal_error.value.status_code == 400
    assert "Invalid project path" in traversal_error.value.detail


def test_traversal_is_rejected_before_filesystem_resolution(monkeypatch):
    request = routes.ScanRequest(project_path="../outside")

    def deny_resolution(*_args, **_kwargs):
        raise AssertionError("Path resolution must not occur for traversal input")

    monkeypatch.setattr(Path, "resolve", deny_resolution)

    with pytest.raises(HTTPException) as error:
        routes.scan(request)

    assert error.value.status_code == 400


def test_scan_rejects_overlong_paths_without_echoing_input(tmp_path, monkeypatch):
    monkeypatch.setattr(routes, "WORKSPACE_ROOT", tmp_path)
    request_path = str(tmp_path / ("private-user-" + "x" * 500))

    with pytest.raises(HTTPException) as error:
        routes.scan(routes.ScanRequest(project_path=request_path))

    assert error.value.status_code == 400
    assert "private-user" not in error.value.detail


def test_scan_rejects_symlink_to_outside_workspace(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside"
    workspace.mkdir()
    outside.mkdir()
    (outside / "source.py").write_text("value = 1\n", encoding="utf-8")
    link = workspace / "linked"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation is not available in this environment")

    monkeypatch.setattr(routes, "WORKSPACE_ROOT", workspace)

    with pytest.raises(HTTPException) as error:
        routes.scan(routes.ScanRequest(project_path="linked"))

    assert error.value.status_code == 400
    assert "inside the workspace" in error.value.detail


def test_scan_accepts_a_supported_source_file(tmp_path, monkeypatch):
    source = tmp_path / "unsafe.js"
    source.write_text("eval(input)\n", encoding="utf-8")
    monkeypatch.setattr(routes, "WORKSPACE_ROOT", tmp_path)
    monkeypatch.setattr(routes, "save_scan", lambda _path, _result: None)

    response = routes.scan(routes.ScanRequest(project_path=source.name))

    assert response["total_findings"] == 1
    assert response["findings"][0]["language"] == "JavaScript"


def test_scan_response_and_persistence_use_relative_paths(tmp_path, monkeypatch):
    source = tmp_path / "source.py"
    source.write_text("value = 1\n", encoding="utf-8")
    saved = []
    monkeypatch.setattr(routes, "WORKSPACE_ROOT", tmp_path)
    monkeypatch.setattr(
        routes,
        "scan_project",
        lambda _path: {
            "status": "partial",
            "total_findings": 1,
            "findings": [{
                "filename": str(source),
                "test_id": "SEC001",
            }],
            "errors": [{
                "path": str(source),
                "message": "Source file scan failed (SyntaxError).",
            }],
        },
    )
    monkeypatch.setattr(
        routes, "save_scan", lambda path, result: saved.append((path, result))
    )

    response = routes.scan(routes.ScanRequest(project_path=source.name))

    assert response["findings"][0]["filename"] == "source.py"
    assert response["errors"][0]["path"] == "source.py"
    assert saved[0][0] == "source.py"
    assert saved[0][1]["findings"][0]["filename"] == "source.py"
    assert str(tmp_path) not in str(response)
    assert str(tmp_path) not in str(saved)


def test_scan_redacts_paths_outside_workspace(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "private-user" / "external.py"
    source = workspace / "source.py"
    source.write_text("value = 1\n", encoding="utf-8")
    monkeypatch.setattr(routes, "WORKSPACE_ROOT", workspace)
    monkeypatch.setattr(
        routes,
        "scan_project",
        lambda _path: {
            "status": "partial",
            "total_findings": 0,
            "findings": [],
            "errors": [{
                "path": str(outside),
                "message": "Source file scan failed (PermissionError).",
            }],
        },
    )
    monkeypatch.setattr(routes, "save_scan", lambda _path, _result: None)

    response = routes.scan(routes.ScanRequest(project_path="source.py"))

    assert response["errors"][0]["path"] == "<outside-workspace>"
    assert "private-user" not in str(response)


def test_watcher_api_redacts_paths_outside_workspace(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setattr(routes, "WORKSPACE_ROOT", workspace)
    monkeypatch.setattr(
        app_main,
        "watcher_state",
        {
            "running": True,
            "last_file": str(tmp_path / "private-user" / "source.py"),
            "last_findings": [],
            "last_error": None,
        },
    )

    status = app_main.get_watcher_status()
    findings = app_main.get_watcher_findings()

    assert status["last_file"] == "<outside-workspace>"
    assert findings["last_file"] == "<outside-workspace>"
    assert "private-user" not in str(status)
    assert "private-user" not in str(findings)


def test_history_and_statistics_redact_legacy_absolute_paths(tmp_path, monkeypatch):
    absolute_path = tmp_path / "private-user" / "project"
    monkeypatch.setattr(routes, "WORKSPACE_ROOT", tmp_path / "workspace")
    routes.WORKSPACE_ROOT.mkdir()
    monkeypatch.setattr(
        routes,
        "get_scan_history",
        lambda _limit: [{
            "project_path": str(absolute_path),
            "status": "failed",
            "findings": [{
                "filename": str(absolute_path / "source.py"),
                "test_id": "SEC001",
            }],
            "errors": [{
                "path": str(absolute_path / "source.py"),
                "message": "Source file scan failed (SyntaxError).",
            }],
        }],
    )
    monkeypatch.setattr(
        routes,
        "get_scan_statistics",
        lambda: {
            "total_scans": 1,
            "total_findings": 0,
            "high_severity_findings": 0,
            "latest_scan": {"project_path": str(absolute_path)},
        },
    )

    history = routes.scan_history()
    statistics = routes.scan_statistics()

    assert history["scans"][0]["project_path"] == "<outside-workspace>"
    assert history["scans"][0]["findings"][0]["filename"] == (
        "<outside-workspace>"
    )
    assert history["scans"][0]["errors"][0]["path"] == "<outside-workspace>"
    assert statistics["latest_scan"]["project_path"] == "<outside-workspace>"
    assert "private-user" not in str(history)
    assert "private-user" not in str(statistics)


def test_windows_absolute_history_paths_are_redacted_on_other_platforms(
    tmp_path, monkeypatch
):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setattr(routes, "WORKSPACE_ROOT", workspace)
    monkeypatch.setattr(
        routes,
        "get_scan_history",
        lambda _limit: [{
            "project_path": r"C:\Users\private-user\project",
            "status": "failed",
            "findings": [{
                "filename": r"C:\Users\private-user\project\source.py",
            }],
            "errors": [{
                "path": r"C:\Users\private-user\project\source.py",
                "message": "Source file scan failed (SyntaxError).",
            }],
        }],
    )

    history = routes.scan_history()

    assert history["scans"][0]["project_path"] == "<outside-workspace>"
    assert history["scans"][0]["findings"][0]["filename"] == (
        "<outside-workspace>"
    )
    assert history["scans"][0]["errors"][0]["path"] == "<outside-workspace>"
    assert "private-user" not in str(history)


def test_scan_returns_and_persists_failed_result(tmp_path, monkeypatch):
    source = tmp_path / "invalid.py"
    source.write_text("def broken(:\n", encoding="utf-8")
    saved = []
    monkeypatch.setattr(routes, "WORKSPACE_ROOT", tmp_path)
    monkeypatch.setattr(
        routes, "save_scan", lambda path, result: saved.append((path, result))
    )

    response = routes.scan(routes.ScanRequest(project_path=source.name))

    assert response["status"] == "failed"
    assert response["errors"][0]["message"] == (
        "Source file scan failed (SyntaxError)."
    )
    assert response["errors"][0]["path"] == "invalid.py"
    assert str(tmp_path) not in str(response)
    assert saved[0][1]["status"] == "failed"


def test_unexpected_scan_failure_is_logged_and_persisted(
    tmp_path, monkeypatch, caplog
):
    import database as route_database

    source = tmp_path / "source.py"
    source.write_text("value = 1\n", encoding="utf-8")
    monkeypatch.setattr(
        route_database, "DATABASE_PATH", tmp_path / "unexpected.db"
    )
    route_database.initialize_database()
    monkeypatch.setattr(routes, "WORKSPACE_ROOT", tmp_path)

    def fail_scan(_path):
        raise RuntimeError("scanner failure")

    monkeypatch.setattr(routes, "scan_project", fail_scan)

    with pytest.raises(HTTPException) as error:
        routes.scan(routes.ScanRequest(project_path=source.name))

    assert error.value.status_code == 500
    history = route_database.get_scan_history()
    assert history[0]["status"] == "failed"
    assert history[0]["project_path"] == "source.py"
    assert history[0]["errors"][0]["path"] == "source.py"
    assert history[0]["errors"][0]["message"] == (
        "Scan failed due to an unexpected scanner error."
    )
    assert "Unexpected scan failure" in caplog.text


def test_scan_history_failure_is_logged_without_claiming_persistence(
    tmp_path, monkeypatch, caplog
):
    source = tmp_path / "source.py"
    source.write_text("value = 1\n", encoding="utf-8")
    monkeypatch.setattr(routes, "WORKSPACE_ROOT", tmp_path)

    def fail_save(_path, _result):
        raise OSError("database unavailable")

    monkeypatch.setattr(routes, "save_scan", fail_save)

    with pytest.raises(HTTPException) as error:
        routes.scan(routes.ScanRequest(project_path=source.name))

    assert error.value.status_code == 500
    assert error.value.detail == "The scan result could not be recorded in history."
    assert "Unable to persist scan history" in caplog.text


def test_failed_scan_history_failure_is_logged_truthfully(
    tmp_path, monkeypatch, caplog
):
    source = tmp_path / "source.py"
    source.write_text("value = 1\n", encoding="utf-8")
    monkeypatch.setattr(routes, "WORKSPACE_ROOT", tmp_path)

    def fail_scan(_path):
        raise RuntimeError("scanner failure")

    def fail_save(_path, _result):
        raise OSError("database unavailable")

    monkeypatch.setattr(routes, "scan_project", fail_scan)
    monkeypatch.setattr(routes, "save_scan", fail_save)

    with pytest.raises(HTTPException) as error:
        routes.scan(routes.ScanRequest(project_path=source.name))

    assert error.value.status_code == 500
    assert error.value.detail == (
        "The scan failed and its failure could not be recorded in history."
    )
    assert "Unable to persist failed scan history" in caplog.text


def test_failed_scan_does_not_overwrite_prior_successful_history(
    tmp_path, monkeypatch
):
    import database as route_database

    source = tmp_path / "source.py"
    database_path = tmp_path / "history.db"
    monkeypatch.setattr(routes, "WORKSPACE_ROOT", tmp_path)
    monkeypatch.setattr(route_database, "DATABASE_PATH", database_path)
    route_database.initialize_database()

    source.write_text("value = 1\n", encoding="utf-8")
    successful_result = routes.scan(routes.ScanRequest(project_path=source.name))
    source.write_text("def broken(:\n", encoding="utf-8")
    failed_result = routes.scan(routes.ScanRequest(project_path=source.name))

    history = route_database.get_scan_history()

    assert successful_result["status"] == "completed"
    assert failed_result["status"] == "failed"
    assert [entry["status"] for entry in history] == ["failed", "completed"]
    assert history[1]["findings"] == successful_result["findings"]
    assert history[0]["project_path"] == "source.py"
    assert history[1]["project_path"] == "source.py"
    assert history[0]["errors"][0]["path"] == "source.py"


@pytest.mark.parametrize(
    ("filename", "contents", "error_type"),
    [
        ("unreadable.py", "value = 1\n", "PermissionError"),
        ("invalid.js", b"\xff", "UnicodeDecodeError"),
        ("malformed.py", "def broken(:\n", "SyntaxError"),
    ],
)
def test_source_failures_never_return_clean_scan(
    filename, contents, error_type, tmp_path, monkeypatch
):
    source = tmp_path / filename
    if isinstance(contents, bytes):
        source.write_bytes(contents)
    else:
        source.write_text(contents, encoding="utf-8")
    monkeypatch.setattr(routes, "WORKSPACE_ROOT", tmp_path)
    monkeypatch.setattr(routes, "save_scan", lambda _path, _result: None)
    if error_type == "PermissionError":
        original_open = open

        def deny_source_open(path, *args, **kwargs):
            if Path(path) == source:
                raise PermissionError("access denied")
            return original_open(path, *args, **kwargs)

        monkeypatch.setattr("builtins.open", deny_source_open)

    result = routes.scan(routes.ScanRequest(project_path=filename))

    assert result["status"] == "failed"
    assert result["total_findings"] == 0
    assert error_type in result["errors"][0]["message"]


def test_watcher_scan_error_is_available_as_error_not_clean_findings(monkeypatch, tmp_path):
    monkeypatch.setattr(
        app_main,
        "watcher_state",
        {
            "running": True,
            "last_file": None,
            "last_findings": [],
            "last_error": None,
        },
    )

    app_main.handle_file_scan_error(tmp_path / "invalid.py", SyntaxError())

    assert app_main.get_watcher_findings()["findings"] == []
    assert app_main.get_watcher_findings()["error"] == (
        "Source file scan failed (SyntaxError)."
    )
