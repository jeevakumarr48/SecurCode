"""Run Trivy filesystem vulnerability and IaC scans and normalize results."""

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


SEVERITY_LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
DEFAULT_THRESHOLD = "HIGH"
SCANNERS = "vuln,misconfig"
SUPPORTED_SCANNER_SETS = {SCANNERS, "misconfig"}


class TrivyError(Exception):
    """Raised when Trivy is missing, fails, or returns unusable output."""


def _optional_text(value):
    return value.strip() if isinstance(value, str) and value.strip() else None


def _finding(target, result_type, language, item):
    if not isinstance(item, dict):
        raise TrivyError(f"Invalid Trivy finding in {target!r}.")

    identifier = (
        item.get("VulnerabilityID")
        if result_type == "vulnerability"
        else item.get("ID")
    )
    severity = _optional_text(item.get("Severity"))
    if not _optional_text(identifier) or not severity:
        raise TrivyError(f"Trivy finding in {target!r} lacks an ID or severity.")

    metadata = item.get("CauseMetadata")
    if metadata is None:
        metadata = {}
    if not isinstance(metadata, dict):
        raise TrivyError(f"Invalid Trivy cause metadata in {target!r}.")

    line_number = metadata.get("StartLine")
    if line_number is not None and (
        not isinstance(line_number, int) or isinstance(line_number, bool) or line_number < 1
    ):
        raise TrivyError(f"Invalid Trivy line number in {target!r}.")

    title = _optional_text(item.get("Title"))
    description = _optional_text(item.get("Description"))
    message = _optional_text(item.get("Message"))
    summary = ": ".join(part for part in (title, description or message) if part)

    finding = {
        "severity": severity.upper(),
        "confidence": "UNKNOWN",
        "test_id": identifier,
        "language": _optional_text(item.get("PkgType")) or language or result_type,
        "filename": target,
        "line_number": line_number,
        "description": summary or f"Trivy {result_type} finding.",
        "scanner": "Trivy",
    }

    for source, destination in (
        ("PkgName", "package_name"),
        ("InstalledVersion", "installed_version"),
        ("FixedVersion", "fixed_version"),
    ):
        value = _optional_text(item.get(source))
        if value:
            finding[destination] = value

    remediation = _optional_text(item.get("Resolution"))
    if not remediation and finding.get("fixed_version"):
        remediation = f"Upgrade to {finding['fixed_version']}."
    if remediation:
        finding["remediation"] = remediation

    resource = _optional_text(metadata.get("Resource"))
    if resource:
        finding["resource"] = resource

    references = item.get("References")
    if isinstance(references, list):
        finding["references"] = [
            reference for reference in references if isinstance(reference, str)
        ]
    elif isinstance(item.get("PrimaryURL"), str):
        finding["references"] = [item["PrimaryURL"]]

    return finding


def parse_trivy_results(payload):
    """Convert Trivy JSON results into the SecurCode finding shape."""
    if not isinstance(payload, dict) or not isinstance(payload.get("Results"), list):
        raise TrivyError("Trivy JSON must contain a Results array.")

    findings = []
    seen = set()
    categories = (
        ("Vulnerabilities", "vulnerability"),
        ("Misconfigurations", "misconfiguration"),
    )
    for result in payload["Results"]:
        if (
            not isinstance(result, dict)
            or not isinstance(result.get("Target"), str)
            or not result["Target"]
        ):
            raise TrivyError("Trivy result is missing a valid Target.")

        target = result["Target"]
        for field, result_type in categories:
            entries = result.get(field)
            if entries is None:
                continue
            if not isinstance(entries, list):
                raise TrivyError(f"Trivy {field} must be an array.")
            for entry in entries:
                finding = _finding(
                    target,
                    result_type,
                    _optional_text(result.get("Type")),
                    entry,
                )
                key = (
                    finding["test_id"],
                    finding["filename"],
                    finding["line_number"],
                    finding.get("package_name"),
                    finding["severity"],
                )
                if key not in seen:
                    seen.add(key)
                    findings.append(finding)
    return findings


def findings_at_threshold(findings, threshold=DEFAULT_THRESHOLD):
    threshold = threshold.strip().upper()
    if threshold not in SEVERITY_LEVELS:
        raise TrivyError(
            f"Invalid severity threshold {threshold!r}; choose "
            f"{', '.join(SEVERITY_LEVELS)}."
        )

    threshold_index = SEVERITY_LEVELS.index(threshold)
    failures = []
    for finding in findings:
        severity = finding.get("severity")
        if severity not in SEVERITY_LEVELS:
            raise TrivyError(f"Trivy returned unsupported severity {severity!r}.")
        if SEVERITY_LEVELS.index(severity) >= threshold_index:
            failures.append(finding)
    return failures


def run_trivy(
    target,
    timeout=300,
    trivy_binary=None,
    skip_dirs=(),
    scanners=SCANNERS,
):
    """Run Trivy without a shell; execution and output errors raise TrivyError."""
    binary = trivy_binary or shutil.which("trivy")
    if not binary:
        raise TrivyError(
            "Trivy was not found on PATH. Install Trivy and retry; see the "
            "Trivy installation instructions in README.md."
        )
    if timeout <= 0:
        raise TrivyError("Trivy timeout must be greater than zero.")
    if scanners not in SUPPORTED_SCANNER_SETS:
        raise TrivyError(
            f"Unsupported Trivy scanner set {scanners!r}; choose "
            f"{', '.join(sorted(SUPPORTED_SCANNER_SETS))}."
        )

    command = [
        binary,
        "fs",
        "--format",
        "json",
        "--scanners",
        scanners,
        "--timeout",
        f"{timeout}s",
        "--exit-code",
        "0",
    ]
    for directory in skip_dirs:
        command.extend(("--skip-dirs", str(directory)))
    command.extend(("--", str(target)))

    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as error:
        raise TrivyError(f"Trivy executable was not found: {binary}") from error
    except subprocess.TimeoutExpired as error:
        raise TrivyError(f"Trivy scan timed out after {timeout} seconds.") from error
    except OSError as error:
        raise TrivyError(f"Could not execute Trivy: {error}") from error
    except UnicodeError as error:
        raise TrivyError(f"Trivy output was not valid text: {error}") from error

    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "no diagnostic output").strip()
        raise TrivyError(
            f"Trivy exited with status {result.returncode}: {detail[:1000]}"
        )

    try:
        payload = json.loads(result.stdout)
    except (json.JSONDecodeError, TypeError) as error:
        raise TrivyError(f"Trivy returned invalid JSON: {error}") from error
    return parse_trivy_results(payload)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", nargs="?", default=".")
    parser.add_argument(
        "--fail-on-severity",
        default=os.environ.get("SECURCODE_FAIL_ON_SEVERITY", DEFAULT_THRESHOLD),
    )
    parser.add_argument("--timeout", type=int, default=300, help="Timeout in seconds.")
    parser.add_argument("--trivy-binary", help="Path to the Trivy executable.")
    parser.add_argument(
        "--scanners",
        choices=sorted(SUPPORTED_SCANNER_SETS),
        default=SCANNERS,
        help="Trivy scanners to run.",
    )
    parser.add_argument(
        "--skip-dir",
        action="append",
        default=[],
        help="Directory to exclude; may be specified more than once.",
    )
    args = parser.parse_args(argv)

    try:
        findings = run_trivy(
            args.target,
            timeout=args.timeout,
            trivy_binary=args.trivy_binary,
            skip_dirs=args.skip_dir,
            scanners=args.scanners,
        )
        failures = findings_at_threshold(findings, args.fail_on_severity)
    except (TrivyError, OSError) as error:
        print(f"Trivy security scan error: {error}", file=sys.stderr)
        return 2

    print(
        f"Trivy filesystem scan completed: {len(findings)} findings; "
        f"threshold {args.fail_on_severity.upper()}."
    )
    for finding in failures:
        print(
            f"{finding['severity']}: {finding['filename']}:"
            f"{finding['line_number'] or '-'} [{finding['test_id']}] "
            f"{finding['description']}"
        )
        if finding.get("remediation"):
            print(f"  Remediation: {finding['remediation']}")

    if failures:
        print(f"Trivy security gate failed with {len(failures)} finding(s).")
        return 1
    print("Trivy security gate passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
