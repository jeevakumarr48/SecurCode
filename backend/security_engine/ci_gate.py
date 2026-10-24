"""Fail-closed CI gate for changed source files."""

import argparse
import os
import subprocess
import sys
from pathlib import Path

from security_engine.scanner.engine import (
    SUPPORTED_EXTENSIONS,
    _should_skip_file,
    scan_file,
)


SEVERITY_LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
DEFAULT_THRESHOLD = "HIGH"


class GateError(Exception):
    """Raised when changed files cannot be scanned reliably."""


def _severity_threshold(value):
    threshold = value.strip().upper()
    if threshold not in SEVERITY_LEVELS:
        choices = ", ".join(SEVERITY_LEVELS)
        raise GateError(f"Invalid severity threshold {value!r}. Choose: {choices}.")
    return threshold


def _changed_files(base_sha, repository):
    if base_sha and set(base_sha) != {"0"}:
        command = [
            "git",
            "diff",
            "--name-only",
            "--diff-filter=ACMR",
            "-z",
            base_sha,
            "HEAD",
        ]
    else:
        command = [
            "git",
            "ls-files",
            "-z",
        ]

    try:
        result = subprocess.run(
            command,
            cwd=repository,
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise GateError(f"Could not determine changed files: {error}") from error

    try:
        return [
            Path(name.decode("utf-8", errors="strict"))
            for name in result.stdout.split(b"\0")
            if name
        ]
    except UnicodeDecodeError as error:
        raise GateError("A changed filename is not valid UTF-8.") from error


def evaluate_files(files, threshold=DEFAULT_THRESHOLD, repository=None):
    """Scan changed files and return findings that meet the configured threshold."""
    threshold = _severity_threshold(threshold)
    repository = Path(repository or Path.cwd()).resolve()
    threshold_index = SEVERITY_LEVELS.index(threshold)
    violations = []

    for relative_path in files:
        relative_path = Path(relative_path)
        if relative_path.is_absolute() or ".." in relative_path.parts:
            raise GateError(f"Changed file escapes the repository: {relative_path}")

        path = repository / relative_path
        if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
            print(f"Skipping unsupported file: {relative_path}")
            continue
        if _should_skip_file(path):
            print(f"Skipping generated file: {relative_path}")
            continue
        if path.is_symlink():
            raise GateError(f"Changed source file is a symlink: {relative_path}")
        if not path.exists() or not path.is_file():
            raise GateError(f"Changed source file is missing or not a file: {relative_path}")

        try:
            findings = scan_file(path, strict=True)
        except Exception as error:
            raise GateError(f"Scanner failed for {relative_path}: {error}") from error

        if not isinstance(findings, list):
            raise GateError(f"Scanner returned invalid results for {relative_path}.")

        for finding in findings:
            severity = finding.get("severity") if isinstance(finding, dict) else None
            if severity not in SEVERITY_LEVELS:
                raise GateError(
                    f"Scanner returned an invalid severity for {relative_path}: "
                    f"{severity!r}."
                )
            if SEVERITY_LEVELS.index(severity) >= threshold_index:
                violations.append(finding)

    return violations


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base-sha",
        default=os.environ.get("SECURCODE_BASE_SHA", ""),
        help="Base commit to compare with HEAD; defaults to the CI environment.",
    )
    parser.add_argument(
        "--fail-on-severity",
        default=os.environ.get("SECURCODE_FAIL_ON_SEVERITY", DEFAULT_THRESHOLD),
        help="Minimum severity that fails the gate (LOW, MEDIUM, HIGH, CRITICAL).",
    )
    args = parser.parse_args(argv)

    try:
        threshold = _severity_threshold(args.fail_on_severity)
        repository = Path(
            subprocess.run(
                ["git", "rev-parse", "--show-toplevel"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
        ).resolve()
        changed_files = _changed_files(args.base_sha, repository)
        print(
            f"Security gate threshold: {threshold}; "
            f"changed paths: {len(changed_files)}."
        )
        violations = evaluate_files(changed_files, threshold, repository)
    except (GateError, OSError, subprocess.CalledProcessError) as error:
        print(f"Security gate error: {error}", file=sys.stderr)
        return 2

    if violations:
        for finding in violations:
            print(
                f"{finding['severity']}: {finding['filename']}:"
                f"{finding['line_number']} [{finding['test_id']}] "
                f"{finding['description']}"
            )
        print(
            f"Security gate failed: {len(violations)} finding(s) meet "
            f"the {threshold} threshold."
        )
        return 1

    print("Security gate passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
