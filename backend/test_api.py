from pathlib import Path
import sys

import pytest
from fastapi import HTTPException

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.api import routes  # noqa: E402


def test_status_uses_securcode_service_name():
    assert routes.status()["service"] == "SecurCode Security Scanner"


def test_scan_rejects_absolute_and_traversal_paths():
    with pytest.raises(HTTPException) as absolute_error:
        routes.scan(routes.ScanRequest(project_path=str(Path.cwd())))
    with pytest.raises(HTTPException) as traversal_error:
        routes.scan(routes.ScanRequest(project_path="../outside"))

    assert absolute_error.value.status_code == 400
    assert traversal_error.value.status_code == 400


def test_scan_accepts_a_supported_source_file(tmp_path, monkeypatch):
    source = tmp_path / "unsafe.js"
    source.write_text("eval(input)\n", encoding="utf-8")
    monkeypatch.setattr(routes, "WORKSPACE_ROOT", tmp_path)
    monkeypatch.setattr(routes, "save_scan", lambda _path, _result: None)

    response = routes.scan(routes.ScanRequest(project_path=source.name))

    assert response["total_findings"] == 1
    assert response["findings"][0]["language"] == "JavaScript"
