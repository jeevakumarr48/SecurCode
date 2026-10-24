import json
import os
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
from pathlib import Path

import pytest

from security_engine.trivy_scan import (
    TrivyError,
    findings_at_threshold,
    parse_trivy_results,
    run_trivy,
)
from security_engine import trivy_scan


TRIVY_FIXTURE = {
    "SchemaVersion": 2,
    "Results": [
        {
            "Target": "backend/requirements.txt",
            "Class": "lang-pkgs",
            "Type": "pip",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2025-12345",
                    "PkgName": "example-package",
                    "InstalledVersion": "1.0",
                    "FixedVersion": "1.2",
                    "Severity": "HIGH",
                    "Title": "Example vulnerability",
                    "Description": "A deterministic test vulnerability.",
                    "PrimaryURL": "https://example.invalid/CVE-2025-12345",
                }
            ],
        },
        {
            "Target": "infra/main.tf",
            "Class": "config",
            "Type": "terraform",
            "Misconfigurations": [
                {
                    "ID": "AVD-AWS-0001",
                    "Severity": "CRITICAL",
                    "Title": "Public storage",
                    "Message": "Storage is publicly accessible.",
                    "Resolution": "Disable public access.",
                    "CauseMetadata": {
                        "StartLine": 12,
                        "Resource": "aws_s3_bucket.data",
                    },
                    "References": ["https://example.invalid/AVD-AWS-0001"],
                }
            ],
        },
    ],
}


def test_parse_trivy_dependency_and_iac_findings_preserving_metadata():
    findings = parse_trivy_results(TRIVY_FIXTURE)

    assert findings == [
        {
            "severity": "HIGH",
            "confidence": "UNKNOWN",
            "test_id": "CVE-2025-12345",
            "language": "pip",
            "filename": "backend/requirements.txt",
            "line_number": None,
            "description": "Example vulnerability: A deterministic test vulnerability.",
            "scanner": "Trivy",
            "package_name": "example-package",
            "installed_version": "1.0",
            "fixed_version": "1.2",
            "remediation": "Upgrade to 1.2.",
            "references": ["https://example.invalid/CVE-2025-12345"],
        },
        {
            "severity": "CRITICAL",
            "confidence": "UNKNOWN",
            "test_id": "AVD-AWS-0001",
            "language": "terraform",
            "filename": "infra/main.tf",
            "line_number": 12,
            "description": "Public storage: Storage is publicly accessible.",
            "scanner": "Trivy",
            "remediation": "Disable public access.",
            "resource": "aws_s3_bucket.data",
            "references": ["https://example.invalid/AVD-AWS-0001"],
        },
    ]


def test_parse_trivy_results_rejects_malformed_output():
    with pytest.raises(TrivyError, match="Results array"):
        parse_trivy_results({"Results": "invalid"})


def test_findings_at_threshold_includes_equal_and_higher_severity():
    findings = parse_trivy_results(TRIVY_FIXTURE)

    assert [finding["test_id"] for finding in findings_at_threshold(findings, "HIGH")] == [
        "CVE-2025-12345",
        "AVD-AWS-0001",
    ]
    assert [finding["test_id"] for finding in findings_at_threshold(findings, "CRITICAL")] == [
        "AVD-AWS-0001",
    ]

def test_cli_returns_nonzero_for_policy_finding(monkeypatch, capsys):
    monkeypatch.setattr(
        trivy_scan,
        "run_trivy",
        lambda *_args, **_kwargs: parse_trivy_results(TRIVY_FIXTURE),
    )

    assert trivy_scan.main(["fixture"]) == 1
    assert "Trivy security gate failed" in capsys.readouterr().out


def test_cli_returns_zero_for_safe_results(monkeypatch, capsys):
    monkeypatch.setattr(trivy_scan, "run_trivy", lambda *_args, **_kwargs: [])

    assert trivy_scan.main(["fixture"]) == 0
    assert "Trivy security gate passed" in capsys.readouterr().out


def test_cli_returns_nonzero_for_scanner_failure(monkeypatch, capsys):
    def fail(*_args, **_kwargs):
        raise TrivyError("scanner failed")

    monkeypatch.setattr(trivy_scan, "run_trivy", fail)

    assert trivy_scan.main(["fixture"]) == 2
    assert "Trivy security scan error: scanner failed" in capsys.readouterr().err


def test_unknown_severity_fails_closed():
    with pytest.raises(TrivyError, match="unsupported severity"):
        findings_at_threshold([{"severity": "UNKNOWN"}])


def test_run_trivy_reports_missing_binary(monkeypatch, tmp_path):
    monkeypatch.setattr("security_engine.trivy_scan.shutil.which", lambda _name: None)

    with pytest.raises(TrivyError, match="not found on PATH"):
        run_trivy(tmp_path)


def test_run_trivy_reports_timeout(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "security_engine.trivy_scan.shutil.which",
        lambda _name: "trivy",
    )

    def timeout(*_args, **_kwargs):
        raise subprocess.TimeoutExpired("trivy", 1)

    monkeypatch.setattr("security_engine.trivy_scan.subprocess.run", timeout)
    with pytest.raises(TrivyError, match="timed out"):
        run_trivy(tmp_path, timeout=1)


@pytest.mark.parametrize(
    ("stdout", "returncode", "message"),
    [
        ("not json", 0, "invalid JSON"),
        ("{}", 0, "Results array"),
        ("", 2, "exited with status 2"),
    ],
)
def test_run_trivy_rejects_errors_and_invalid_output(
    monkeypatch,
    tmp_path,
    stdout,
    returncode,
    message,
):
    monkeypatch.setattr(
        "security_engine.trivy_scan.shutil.which",
        lambda _name: "trivy",
    )
    monkeypatch.setattr(
        "security_engine.trivy_scan.subprocess.run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=returncode,
            stdout=stdout,
            stderr="scanner error",
        ),
    )

    with pytest.raises(TrivyError, match=message):
        run_trivy(tmp_path)


def test_run_trivy_invokes_filesystem_vulnerability_and_iac_scanners(monkeypatch, tmp_path):
    captured = {}
    monkeypatch.setattr(
        "security_engine.trivy_scan.shutil.which",
        lambda _name: "trivy",
    )

    def completed(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps({"Results": []}),
            stderr="",
        )

    monkeypatch.setattr("security_engine.trivy_scan.subprocess.run", completed)
    assert run_trivy(tmp_path, skip_dirs=["generated"]) == []

    assert captured["command"][:6] == [
        "trivy",
        "fs",
        "--format",
        "json",
        "--scanners",
        "vuln,misconfig",
    ]
    assert "--exit-code" in captured["command"]
    assert "--skip-dirs" in captured["command"]
    assert captured["kwargs"]["timeout"] == 300
    assert "shell" not in captured["kwargs"]


def _live_trivy_binary():
    return os.environ.get("SECURCODE_TRIVY_BINARY") or shutil.which("trivy")


@pytest.mark.skipif(not _live_trivy_binary(), reason="Trivy is not installed")
def test_live_trivy_scans_iac_fixture_and_parses_json():
    with tempfile.TemporaryDirectory(prefix="securcode-trivy-live-") as directory:
        target = Path(directory)
        (target / "main.tf").write_text(
            'resource "aws_s3_bucket" "test" {\n'
            '  bucket = "securcode-milestone4a-test"\n'
            '  acl    = "public-read"\n'
            "}\n",
            encoding="utf-8",
        )

        exit_code = trivy_scan.main([
            str(target),
            "--timeout",
            "120",
            "--trivy-binary",
            _live_trivy_binary(),
            "--scanners",
            "misconfig",
            "--fail-on-severity",
            "HIGH",
        ])

    assert exit_code == 1

    with tempfile.TemporaryDirectory(prefix="securcode-trivy-safe-") as directory:
        target = Path(directory)
        (target / "main.tf").write_text(
            'terraform { required_version = ">= 1.0" }\n',
            encoding="utf-8",
        )
        safe_exit_code = trivy_scan.main([
            str(target),
            "--timeout",
            "120",
            "--trivy-binary",
            _live_trivy_binary(),
            "--scanners",
            "misconfig",
            "--fail-on-severity",
            "HIGH",
        ])

    assert safe_exit_code == 0

    with tempfile.TemporaryDirectory(prefix="securcode-trivy-live-parse-") as directory:
        target = Path(directory)
        (target / "main.tf").write_text(
            'resource "aws_s3_bucket" "test" {\n'
            '  bucket = "securcode-milestone4a-test"\n'
            '  acl    = "public-read"\n'
            "}\n",
            encoding="utf-8",
        )
        findings = run_trivy(
            target,
            timeout=120,
            trivy_binary=_live_trivy_binary(),
            scanners="misconfig",
        )

    public_acl_findings = [
        finding
        for finding in findings
        if finding["test_id"] == "AWS-0086"
        and finding["severity"] == "HIGH"
        and finding["line_number"] == 1
        and finding["remediation"]
    ]
    assert public_acl_findings
    assert public_acl_findings[0]["filename"] == "main.tf"


@pytest.mark.skipif(not _live_trivy_binary(), reason="Trivy is not installed")
def test_live_trivy_failure_for_missing_target_is_not_clean(capsys):
    with tempfile.TemporaryDirectory(prefix="securcode-trivy-missing-") as directory:
        missing_target = Path(directory) / "does-not-exist"
        exit_code = trivy_scan.main([
            str(missing_target),
            "--timeout",
            "60",
            "--trivy-binary",
            _live_trivy_binary(),
            "--scanners",
            "misconfig",
        ])

    assert exit_code == 2
    assert "Trivy security scan error" in capsys.readouterr().err
