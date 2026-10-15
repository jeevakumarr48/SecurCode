
import ast
import pytest

from security_engine.scanner.engine import scan_file


def create_python_file(tmp_path, filename, source):
    file_path = tmp_path / filename
    file_path.write_text(source, encoding="utf-8")
    return str(file_path)


def test_detects_eval(tmp_path):
    path = create_python_file(
        tmp_path,
        "unsafe.py",
        "result = eval('1 + 1')\n",
    )

    findings = scan_file(path)

    assert any(
        finding["test_id"] == "SEC001"
        for finding in findings
    )


def test_detects_subprocess_call(tmp_path):
    path = create_python_file(
        tmp_path,
        "unsafe_subprocess.py",
        "import subprocess\n"
        "subprocess.call('echo hello', shell=True)\n",
    )

    findings = scan_file(path)

    assert any(
        finding["test_id"] == "SEC002"
        for finding in findings
    )


def test_safe_code_has_no_findings(tmp_path):
    path = create_python_file(
        tmp_path,
        "safe.py",
        "message = 'hello'\nprint(message)\n",
    )

    findings = scan_file(path)

    assert findings == []


def test_invalid_python_is_handled(tmp_path):
    path = create_python_file(
        tmp_path,
        "invalid.py",
        "def broken(:\n",
    )

    findings = scan_file(path)

    assert findings == []



def test_subprocess_shell_true_is_detected(tmp_path):
    path = create_python_file(
        tmp_path,
        "shell_true.py",
        "import subprocess\n"
        "subprocess.run(['echo', 'hello'], shell=True)\n",
    )

    findings = scan_file(path)

    assert any(
        finding["test_id"] == "SEC002"
        for finding in findings
    )


def test_subprocess_shell_false_is_not_flagged_by_sec002(tmp_path):
    path = create_python_file(
        tmp_path,
        "shell_false.py",
        "import subprocess\n"
        "subprocess.run(['echo', 'hello'], shell=False)\n",
    )

    findings = scan_file(path)

    assert not any(
        finding["test_id"] == "SEC002"
        for finding in findings
    )
