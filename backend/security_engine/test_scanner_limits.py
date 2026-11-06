from types import SimpleNamespace
import time

from security_engine.scanner import engine
from security_engine.scanner.javascript import scan_javascript_file
from security_engine.scanner.python import scan_python_file


def test_python_scanner_resolves_import_aliases_and_safe_yaml_loader(tmp_path):
    source = tmp_path / "aliases.py"
    source.write_text(
        "import subprocess as sp\n"
        "from pickle import loads as decode\n"
        "from os import system as run_command\n"
        "import yaml\n"
        "sp.run(command, shell=True)\n"
        "decode(payload)\n"
        "run_command(value)\n"
        "yaml.load(value, Loader=yaml.FullLoader)\n"
        "yaml.load(value, Loader=yaml.SafeLoader)\n",
        encoding="utf-8",
    )

    findings = scan_python_file(str(source))

    assert [item["test_id"] for item in findings].count("SEC002") == 1
    assert [item["test_id"] for item in findings].count("PYSEC002") == 1
    assert [item["test_id"] for item in findings].count("PYSEC003") == 2


def test_javascript_masking_ignores_comments_and_strings_and_checks_multiline_spawn(tmp_path):
    source = tmp_path / "sample.js"
    source.write_text(
        'const example = "eval(userInput)"; // exec(command)\n'
        "/* eval(source); */\n"
        "spawn(command, {\n"
        "  shell: true,\n"
        "});\n",
        encoding="utf-8",
    )

    findings = scan_javascript_file(str(source))

    assert [item["test_id"] for item in findings] == ["JSSEC004"]
    assert findings[0]["line_number"] == 3


def test_project_scan_limits_file_count_and_source_size(tmp_path, monkeypatch):
    monkeypatch.setattr(engine, "settings", SimpleNamespace(max_scan_files=1, max_source_file_bytes=16, max_scan_bytes=100))
    (tmp_path / "a.py").write_text("value = 1\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("value = 'this source is too large'\n", encoding="utf-8")

    result = engine.scan_project(str(tmp_path))

    assert result["status"] == "partial"
    assert any("file limit" in error["message"] for error in result["errors"])


def test_single_oversized_source_is_not_read(tmp_path, monkeypatch):
    monkeypatch.setattr(engine, "settings", SimpleNamespace(max_scan_files=10, max_source_file_bytes=16, max_scan_bytes=100))
    source = tmp_path / "large.py"
    source.write_text("value = 'this source is too large'\n", encoding="utf-8")

    result = engine.scan_project(str(source))

    assert result["status"] == "failed"
    assert "size limit" in result["errors"][0]["message"]


def test_project_scan_does_not_descend_past_configured_depth(tmp_path, monkeypatch):
    monkeypatch.setattr(engine, "settings", SimpleNamespace(
        max_scan_files=10,
        max_scan_depth=2,
        max_scan_seconds=30,
        max_source_file_bytes=1024,
        max_scan_bytes=4096,
    ))
    allowed = tmp_path / "level-one" / "allowed.py"
    blocked = tmp_path / "level-one" / "level-two" / "level-three" / "blocked.py"
    allowed.parent.mkdir(parents=True)
    blocked.parent.mkdir(parents=True)
    allowed.write_text("value = 1\n", encoding="utf-8")
    blocked.write_text("import pickle\npickle.loads(payload)\n", encoding="utf-8")

    result = engine.scan_project(str(tmp_path))

    assert result["status"] == "partial"
    assert result["total_findings"] == 0
    assert any("depth limit" in error["message"] for error in result["errors"])


def test_project_scan_stops_between_files_at_time_budget(tmp_path, monkeypatch):
    monkeypatch.setattr(engine, "settings", SimpleNamespace(
        max_scan_files=10,
        max_scan_depth=10,
        max_scan_seconds=1,
        max_source_file_bytes=1024,
        max_scan_bytes=4096,
    ))
    source = tmp_path / "slow.py"
    source.write_text("value = 1\n", encoding="utf-8")
    original = engine._scan_source_file

    def slow_scan(filename):
        time.sleep(1.02)
        return original(filename)

    monkeypatch.setattr(engine, "_scan_source_file", slow_scan)
    result = engine.scan_project(str(tmp_path))

    assert result["status"] == "partial"
    assert any("time limit" in error["message"] for error in result["errors"])
