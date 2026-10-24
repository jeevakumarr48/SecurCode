from pathlib import Path

import pytest

from security_engine.scanner.engine import scan_file, scan_project


def write_source(tmp_path, filename, source):
    path = tmp_path / filename
    path.write_text(source, encoding="utf-8")
    return str(path)


def test_python_extended_rules_have_standard_fields(tmp_path):
    path = write_source(
        tmp_path,
        "unsafe.py",
        "import pickle\n"
        "password = 'real-password-value'\n"
        "payload = pickle.loads(raw_data)\n"
        "cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")\n",
    )

    findings = scan_file(path)
    rule_ids = {finding["test_id"] for finding in findings}

    assert {"PYSEC003", "PYSEC004", "PYSEC006"}.issubset(rule_ids)
    assert all(finding["language"] == "Python" for finding in findings)
    assert all({
        "severity",
        "confidence",
        "test_id",
        "language",
        "filename",
        "line_number",
        "description",
    }.issubset(finding) for finding in findings)


def test_python_safe_patterns_are_not_reported(tmp_path):
    path = write_source(
        tmp_path,
        "safe.py",
        "import os\n"
        "password = os.getenv('APP_PASSWORD')\n"
        "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))\n",
    )

    assert scan_file(path) == []


def test_javascript_and_typescript_rules_are_detected(tmp_path):
    javascript_path = write_source(
        tmp_path,
        "unsafe.js",
        "const value = eval(input);\n"
        "require('child_process').exec(command);\n"
        "const API_KEY = 'long-secret-value';\n",
    )
    typescript_path = write_source(
        tmp_path,
        "unsafe.ts",
        "const factory = new Function(source);\n"
        "spawn(command, { shell: true });\n",
    )

    javascript_findings = scan_file(javascript_path)
    typescript_findings = scan_file(typescript_path)

    assert {finding["test_id"] for finding in javascript_findings} == {"JSSEC001", "JSSEC003", "JSSEC005"}
    assert {finding["test_id"] for finding in typescript_findings} == {"JSSEC002", "JSSEC004"}
    assert all(finding["language"] == "JavaScript" for finding in javascript_findings)
    assert all(finding["language"] == "TypeScript" for finding in typescript_findings)


def test_safe_javascript_and_malformed_sources_do_not_crash(tmp_path):
    safe_path = write_source(
        tmp_path,
        "safe.tsx",
        "const token = process.env.API_TOKEN;\n"
        "const query = await db.query('SELECT 1');\n",
    )
    malformed_path = write_source(tmp_path, "malformed.jsx", "const broken = {\n")

    assert scan_file(safe_path) == []
    assert isinstance(scan_file(malformed_path), list)


def test_unreadable_python_source_fails_project_scan(monkeypatch, tmp_path):
    path = write_source(tmp_path, "blocked.py", "value = 1\n")

    def deny_open(*_args, **_kwargs):
        raise PermissionError("access denied")

    monkeypatch.setattr("builtins.open", deny_open)

    result = scan_project(str(tmp_path))

    assert result["status"] == "failed"
    assert result["total_findings"] == 0
    assert result["errors"] == [{
        "path": path,
        "message": "Source file scan failed (PermissionError).",
    }]


def test_project_scan_discovers_supported_files_and_skips_generated_dependencies(tmp_path):
    source_dir = tmp_path / "src"
    dependency_dir = tmp_path / "node_modules"
    generated_dir = tmp_path / "dist"
    source_dir.mkdir()
    dependency_dir.mkdir()
    generated_dir.mkdir()
    write_source(source_dir, "app.js", "eval(input)\n")
    write_source(dependency_dir, "vendor.js", "eval(input)\n")
    write_source(generated_dir, "bundle.js", "eval(input)\n")

    result = scan_project(str(tmp_path))

    assert result["total_findings"] == 1
    finding_path = Path(result["findings"][0]["filename"])
    assert finding_path.parent.name == "src"
    assert finding_path.name == "app.js"


def test_project_scan_does_not_follow_symlinked_source(tmp_path):
    external_file = tmp_path.parent / "external-unsafe.js"
    external_file.write_text("eval(input)\n", encoding="utf-8")
    symlink = tmp_path / "linked.js"
    try:
        symlink.symlink_to(external_file)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation is not available in this Windows environment")

    result = scan_project(str(tmp_path))

    assert result["findings"] == []
    assert result["status"] == "failed"
    assert result["errors"] == [{
        "path": str(symlink),
        "message": "Symbolic link source file was not scanned.",
    }]


def test_project_scan_reports_directory_traversal_errors(monkeypatch, tmp_path):
    def failed_walk(path, followlinks, onerror):
        onerror(PermissionError(13, "access denied", str(path / "restricted")))
        yield str(path), [], []

    monkeypatch.setattr("security_engine.scanner.engine.os.walk", failed_walk)

    result = scan_project(str(tmp_path))

    assert result["status"] == "failed"
    assert result["errors"] == [{
        "path": str(tmp_path / "restricted"),
        "message": "Directory traversal failed (PermissionError).",
    }]


def test_project_scan_reports_decoding_errors(tmp_path):
    (tmp_path / "invalid.js").write_bytes(b"\xff")

    result = scan_project(str(tmp_path))

    assert result["status"] == "failed"
    assert result["errors"][0]["message"] == (
        "Source file scan failed (UnicodeDecodeError)."
    )


def test_project_scan_reports_python_parser_errors(tmp_path):
    write_source(tmp_path, "invalid.py", "def broken(:\n")

    result = scan_project(str(tmp_path))

    assert result["status"] == "failed"
    assert result["errors"][0]["message"] == (
        "Source file scan failed (SyntaxError)."
    )


def test_project_scan_reports_unexpected_scanner_errors(monkeypatch, tmp_path):
    write_source(tmp_path, "source.py", "value = 1\n")

    def fail_scan(_filename):
        raise RuntimeError("scanner failure")

    monkeypatch.setattr("security_engine.scanner.engine._scan_source_file", fail_scan)

    result = scan_project(str(tmp_path))

    assert result["status"] == "failed"
    assert result["errors"][0]["message"] == (
        "Source file scan failed (RuntimeError)."
    )


def test_project_scan_marks_mixed_success_and_failure_partial(tmp_path):
    write_source(tmp_path, "safe.py", "value = 1\n")
    write_source(tmp_path, "invalid.py", "def broken(:\n")

    result = scan_project(str(tmp_path))

    assert result["status"] == "partial"
    assert result["errors"][0]["message"] == (
        "Source file scan failed (SyntaxError)."
    )


def test_project_scan_does_not_report_missing_target_as_clean(tmp_path):
    result = scan_project(str(tmp_path / "missing"))

    assert result["status"] == "failed"
    assert result["total_findings"] == 0
    assert result["errors"][0]["message"] == (
        "Source discovery failed (FileNotFoundError)."
    )


def test_project_scan_rejects_unsupported_target_file(tmp_path):
    target = tmp_path / "notes.txt"
    target.write_text("not source code\n", encoding="utf-8")

    result = scan_project(str(target))

    assert result["status"] == "failed"
    assert result["errors"] == [{
        "path": str(target),
        "message": "Target file extension is not supported.",
    }]
