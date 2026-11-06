import json
import io

import pytest

from security_engine import integrations
from security_engine.integrations import IntegrationError


def test_sarif_import_maps_rule_cwe_severity_and_relative_location():
    findings = integrations.parse_sarif({
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "CodeQL", "rules": [{
                "id": "py/sql-injection",
                "shortDescription": {"text": "SQL injection"},
                "properties": {"tags": ["external/cwe/cwe-89"], "security-severity": "8.1"},
            }]}},
            "results": [{
                "ruleId": "py/sql-injection",
                "level": "error",
                "message": {"text": "Untrusted query input reaches execute."},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "src/db.py"},
                    "region": {"startLine": 17, "startColumn": 4},
                }}],
            }],
        }],
    })

    assert len(findings) == 1
    assert findings[0]["scanner"] == "CodeQL"
    assert findings[0]["cwe"] == "CWE-89"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["filename"] == "src/db.py"
    assert findings[0]["line_number"] == 17


@pytest.mark.parametrize("path", ["../secrets.py", "/private/repo/file.py", "file:///C:/private/file.py"])
def test_sarif_paths_outside_workspace_are_redacted(path):
    assert integrations._safe_sarif_path(path) == "<outside-workspace>"


def test_gitleaks_normalization_never_returns_secret_material():
    findings = integrations._parse_gitleaks([{
        "RuleID": "aws-access-token",
        "Description": "AWS Access Key",
        "File": "config.py",
        "StartLine": 9,
        "Secret": "AKIA1234567890EXAMPLE",
        "Match": "secret=AKIA1234567890EXAMPLE",
    }])

    assert findings[0]["test_id"] == "aws-access-token"
    assert "AKIA1234567890EXAMPLE" not in json.dumps(findings)
    assert "Secret" not in findings[0]


def test_bandit_and_semgrep_results_normalize_to_shared_shape():
    bandit = integrations._parse_bandit({"results": [{
        "test_id": "B608", "issue_severity": "MEDIUM", "issue_confidence": "HIGH",
        "issue_text": "Possible SQL injection", "filename": "db.py", "line_number": 8,
        "issue_cwe": {"id": 89},
    }]})
    semgrep = integrations._parse_semgrep({"results": [{
        "check_id": "python.lang.security.audit.subprocess-shell-true",
        "path": "worker.py", "lang": "python", "start": {"line": 5},
        "extra": {"severity": "ERROR", "message": "Shell is enabled", "metadata": {"cwe": ["CWE-78"]}},
    }]})

    assert bandit[0]["cwe"] == "CWE-89"
    assert bandit[0]["scanner"] == "Bandit"
    assert semgrep[0]["severity"] == "HIGH"
    assert semgrep[0]["cwe"] == "CWE-78"


def test_unknown_tool_and_missing_binary_fail_without_execution(monkeypatch, tmp_path):
    monkeypatch.setattr(integrations.shutil, "which", lambda _name: None)
    with pytest.raises(IntegrationError, match="not found on PATH"):
        integrations.run_optional_scanner("bandit", tmp_path)
    with pytest.raises(IntegrationError, match="Choose"):
        integrations.run_optional_scanner("arbitrary.exe", tmp_path)


def test_json_runner_uses_bounded_timeout_and_reports_structured_output(monkeypatch, tmp_path):
    captured = {}

    class FakeProcess:
        stdout = io.BytesIO(b'{"results": []}')
        stderr = io.BytesIO(b"")
        returncode = 0
        def wait(self, timeout=None):
            captured["timeout"] = timeout
            return self.returncode
        def kill(self):
            captured["killed"] = True

    def launch(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return FakeProcess()

    monkeypatch.setattr(integrations.subprocess, "Popen", launch)
    payload = integrations._run_json(["bandit", "-f", "json"], timeout=5, cwd=tmp_path)
    assert payload == {"results": []}
    assert captured["kwargs"]["shell"] is False
    assert captured["timeout"] == 5

    class TimeoutProcess(FakeProcess):
        calls = 0
        def wait(self, timeout=None):
            self.calls += 1
            if self.calls == 1:
                raise integrations.subprocess.TimeoutExpired("scanner", timeout)
            return -9

    monkeypatch.setattr(integrations.subprocess, "Popen", lambda *_args, **_kwargs: TimeoutProcess())
    with pytest.raises(IntegrationError, match="timeout"):
        integrations._run_json(["bandit"], timeout=1, cwd=tmp_path)


def test_json_runner_caps_output_without_echoing_scanner_diagnostics(monkeypatch, tmp_path):
    monkeypatch.setattr(integrations, "MAX_OUTPUT_BYTES", 10)
    class FakeProcess:
        def __init__(self, stdout=b"", stderr=b"", returncode=0):
            self.stdout = io.BytesIO(stdout)
            self.stderr = io.BytesIO(stderr)
            self.returncode = returncode
        def wait(self, timeout=None):
            return self.returncode
        def kill(self):
            return None
    monkeypatch.setattr(integrations.subprocess, "Popen", lambda *_args, **_kwargs: FakeProcess(stdout=b"x" * 50))
    with pytest.raises(IntegrationError, match="output limit"):
        integrations._run_json(["scanner"], timeout=5, cwd=tmp_path)

    monkeypatch.setattr(integrations.subprocess, "Popen", lambda *_args, **_kwargs: FakeProcess(stderr=b"sensitive", returncode=2))
    with pytest.raises(IntegrationError, match="status 2") as failed:
        integrations._run_json(["scanner"], timeout=5, cwd=tmp_path)
    assert "sensitive" not in str(failed.value)
