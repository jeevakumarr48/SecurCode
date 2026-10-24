import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from security_engine import ci_gate
from security_engine.ci_gate import GateError, _changed_files, evaluate_files


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DEMO_DIRECTORY = Path("backend/app/api/docs/security-demo")


def test_ci_gate_rejects_vulnerable_fixture_at_default_threshold():
    violations = evaluate_files(
        [DEMO_DIRECTORY / "vulnerable.py"],
        repository=REPOSITORY_ROOT,
    )

    assert any(finding["test_id"] == "SEC001" for finding in violations)


def test_ci_gate_accepts_safe_fixture_at_default_threshold():
    violations = evaluate_files(
        [
            DEMO_DIRECTORY / "safe-example.py",
            DEMO_DIRECTORY / "safe_example.py",
        ],
        repository=REPOSITORY_ROOT,
    )

    assert violations == []


def test_ci_gate_threshold_is_configurable(tmp_path):
    source = tmp_path / "credential.py"
    source.write_text('password = "long-password-value"\n', encoding="utf-8")

    assert evaluate_files([source.name], repository=tmp_path) == []
    assert len(evaluate_files(
        [source.name],
        threshold="MEDIUM",
        repository=tmp_path,
    )) == 1


def test_cli_returns_failure_for_vulnerable_fixture(monkeypatch, capsys):
    monkeypatch.setattr(
        ci_gate.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(stdout=f"{REPOSITORY_ROOT}\n"),
    )
    monkeypatch.setattr(
        ci_gate,
        "_changed_files",
        lambda _base_sha, _repository: [DEMO_DIRECTORY / "vulnerable.py"],
    )

    assert ci_gate.main(["--fail-on-severity", "HIGH"]) == 1
    assert "Security gate failed" in capsys.readouterr().out


def test_cli_returns_success_for_safe_fixture(monkeypatch, capsys):
    monkeypatch.setattr(
        ci_gate.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(stdout=f"{REPOSITORY_ROOT}\n"),
    )
    monkeypatch.setattr(
        ci_gate,
        "_changed_files",
        lambda _base_sha, _repository: [DEMO_DIRECTORY / "safe-example.py"],
    )

    assert ci_gate.main(["--fail-on-severity", "HIGH"]) == 0
    assert "Security gate passed" in capsys.readouterr().out


def test_ci_gate_rejects_missing_changed_source(tmp_path):
    with pytest.raises(GateError, match="missing or not a file"):
        evaluate_files(["deleted.py"], repository=tmp_path)


def test_ci_gate_skips_unsupported_changed_file(tmp_path, capsys):
    (tmp_path / "notes.txt").write_text("not source code", encoding="utf-8")

    assert evaluate_files(["notes.txt"], repository=tmp_path) == []
    assert "Skipping unsupported file" in capsys.readouterr().out


def test_ci_gate_fails_closed_for_python_syntax_errors(tmp_path):
    malformed = tmp_path / "malformed.py"
    malformed.write_text("def broken(:\n", encoding="utf-8")

    with pytest.raises(GateError, match="Scanner failed"):
        evaluate_files([malformed.name], repository=tmp_path)


def test_changed_files_include_edits_and_additions_but_not_deletions(tmp_path):
    def git(*args):
        return subprocess.run(
            ["git", *args],
            cwd=tmp_path,
            check=True,
            capture_output=True,
            stdin=subprocess.DEVNULL,
            text=True,
        ).stdout.strip()

    git("init", "-q")
    git("config", "user.email", "test@example.invalid")
    git("config", "user.name", "CI Gate Test")
    (tmp_path / "changed.py").write_text("value = 1\n", encoding="utf-8")
    (tmp_path / "deleted.py").write_text("value = 1\n", encoding="utf-8")
    git("add", ".")
    git("commit", "-qm", "baseline")
    base_sha = git("rev-parse", "HEAD")

    (tmp_path / "changed.py").write_text("eval(input)\n", encoding="utf-8")
    (tmp_path / "deleted.py").unlink()
    (tmp_path / "notes.txt").write_text("not source", encoding="utf-8")
    git("add", "-A")
    git("commit", "-qm", "source changes")

    changed = _changed_files(base_sha, tmp_path)

    assert changed == [Path("changed.py"), Path("notes.txt")]


@pytest.mark.parametrize("base_sha", ["", "0" * 40])
def test_changed_files_fall_back_to_tracked_files_without_base_sha(
    monkeypatch,
    tmp_path,
    base_sha,
):
    captured = {}

    def run(command, **_kwargs):
        captured["command"] = command
        return SimpleNamespace(stdout=b"tracked.py\0")

    monkeypatch.setattr(ci_gate.subprocess, "run", run)

    assert _changed_files(base_sha, tmp_path) == [Path("tracked.py")]
    assert captured["command"] == ["git", "ls-files", "-z"]
