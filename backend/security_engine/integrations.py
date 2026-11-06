"""Optional external scanner runners and SARIF normalization.

No tool is downloaded or installed automatically. Executables are resolved by
their fixed command name on PATH; callers cannot pass arbitrary executable paths.
"""

import json
import shutil
import subprocess
from threading import Thread
from pathlib import Path
from urllib.parse import unquote, urlsplit


TOOLS = {"semgrep", "bandit", "gitleaks", "trivy"}
MAX_OUTPUT_BYTES = 25 * 1024 * 1024
MAX_FINDINGS = 50000
SEVERITY = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"}


class IntegrationError(Exception):
    """Optional integration is unavailable or returned invalid output."""


def _safe_severity(value):
    value = str(value or "UNKNOWN").upper()
    return value if value in SEVERITY else "UNKNOWN"


def _semgrep_severity(value):
    return {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}.get(str(value).upper(), "UNKNOWN")


def _sarif_severity(level, security_severity=None):
    try:
        score = float(security_severity)
    except (TypeError, ValueError):
        score = None
    if score is not None:
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        return "LOW"
    return {"error": "HIGH", "warning": "MEDIUM", "note": "LOW", "none": "INFO"}.get(str(level).lower(), "UNKNOWN")


def _safe_sarif_path(value):
    if not isinstance(value, str) or not value:
        return "<unknown-file>"
    parsed = urlsplit(value)
    decoded = unquote(value)
    normalized = decoded.replace("\\", "/")
    if parsed.scheme or normalized.startswith("/") or any(part == ".." for part in normalized.split("/")):
        return "<outside-workspace>"
    return normalized.removeprefix("./")


def _cwe_from(value):
    if not isinstance(value, (str, list, tuple)):
        return None
    text = " ".join(value) if isinstance(value, (list, tuple)) else value
    import re
    match = re.search(r"CWE[-/: ]?(\d+)", text, re.IGNORECASE)
    return f"CWE-{match.group(1)}" if match else None


def parse_sarif(payload, source="SARIF"):
    """Normalize SARIF 2.x results while retaining file/line/rule attribution."""
    if not isinstance(payload, dict) or not isinstance(payload.get("runs"), list):
        raise IntegrationError("SARIF document must contain a runs array.")
    findings = []
    for run in payload["runs"]:
        if not isinstance(run, dict):
            raise IntegrationError("SARIF run must be an object.")
        tool = run.get("tool", {}).get("driver", {}) if isinstance(run.get("tool"), dict) else {}
        scanner = tool.get("name") if isinstance(tool.get("name"), str) else source
        rules = {}
        for rule in tool.get("rules", []) if isinstance(tool.get("rules", []), list) else []:
            if isinstance(rule, dict) and isinstance(rule.get("id"), str):
                rules[rule["id"]] = rule
        results = run.get("results", [])
        if not isinstance(results, list):
            raise IntegrationError("SARIF run results must be an array.")
        for result in results:
            if len(findings) >= MAX_FINDINGS:
                raise IntegrationError(f"SARIF results exceed the {MAX_FINDINGS}-finding limit.")
            if not isinstance(result, dict) or not isinstance(result.get("ruleId"), str):
                raise IntegrationError("SARIF result is missing a ruleId.")
            rule_id = result["ruleId"]
            rule = rules.get(rule_id, {})
            properties = rule.get("properties", {}) if isinstance(rule.get("properties"), dict) else {}
            message = result.get("message", {})
            message_text = message.get("text") if isinstance(message, dict) else None
            locations = result.get("locations", [])
            location = locations[0] if locations and isinstance(locations[0], dict) else {}
            physical = location.get("physicalLocation", {}) if isinstance(location.get("physicalLocation"), dict) else {}
            artifact = physical.get("artifactLocation", {}) if isinstance(physical.get("artifactLocation"), dict) else {}
            region = physical.get("region", {}) if isinstance(physical.get("region"), dict) else {}
            uri = artifact.get("uri")
            line = region.get("startLine")
            if line is not None and (not isinstance(line, int) or isinstance(line, bool) or line < 1):
                line = None
            tags = properties.get("tags", [])
            cwe = _cwe_from(tags)
            security_severity = properties.get("security-severity")
            short = rule.get("shortDescription", {})
            title = short.get("text") if isinstance(short, dict) else None
            findings.append({
                "severity": _sarif_severity(result.get("level"), security_severity),
                "confidence": "UNKNOWN",
                "test_id": rule_id,
                "cwe": cwe,
                "language": "Unknown",
                "filename": _safe_sarif_path(uri),
                "line_number": line,
                "description": str(message_text or title or f"{scanner} finding {rule_id}")[:4000],
                "scanner": scanner,
                "remediation": properties.get("remediation") if isinstance(properties.get("remediation"), str) else "Review the scanner guidance and validate the finding.",
            })
    return findings


def _parse_semgrep(payload):
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
        raise IntegrationError("Semgrep JSON must contain results.")
    findings = []
    for item in payload["results"]:
        if not isinstance(item, dict):
            continue
        extra = item.get("extra", {}) if isinstance(item.get("extra"), dict) else {}
        start = item.get("start", {}) if isinstance(item.get("start"), dict) else {}
        metadata = extra.get("metadata", {}) if isinstance(extra.get("metadata"), dict) else {}
        findings.append({
            "severity": _semgrep_severity(extra.get("severity")),
            "confidence": str(metadata.get("confidence", "UNKNOWN")).upper(),
            "test_id": str(item.get("check_id", "SEMGREP-UNKNOWN")),
            "cwe": _cwe_from(metadata.get("cwe")),
            "language": str(item.get("lang", "Unknown")),
            "filename": str(item.get("path", "<unknown-file>")),
            "line_number": start.get("line") if isinstance(start.get("line"), int) else None,
            "description": str(extra.get("message", "Semgrep finding"))[:4000],
            "scanner": "Semgrep",
            "remediation": str(extra.get("fix", "Review the Semgrep finding and apply a safe fix."))[:2000],
        })
    return findings


def _parse_bandit(payload):
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
        raise IntegrationError("Bandit JSON must contain results.")
    findings = []
    for item in payload["results"]:
        if not isinstance(item, dict):
            continue
        cwe = item.get("issue_cwe", {})
        cwe = f"CWE-{cwe['id']}" if isinstance(cwe, dict) and isinstance(cwe.get("id"), int) else None
        findings.append({
            "severity": _safe_severity(item.get("issue_severity")),
            "confidence": str(item.get("issue_confidence", "UNKNOWN")).upper(),
            "test_id": str(item.get("test_id", "BANDIT-UNKNOWN")),
            "cwe": cwe,
            "language": "Python",
            "filename": str(item.get("filename", "<unknown-file>")),
            "line_number": item.get("line_number") if isinstance(item.get("line_number"), int) else None,
            "description": str(item.get("issue_text", "Bandit finding"))[:4000],
            "scanner": "Bandit",
            "remediation": "Review Bandit's rule guidance and validate the finding.",
        })
    return findings


def _parse_gitleaks(payload):
    if not isinstance(payload, list):
        raise IntegrationError("Gitleaks JSON must be an array.")
    findings = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        # Secret, Match, and entropy values are deliberately never returned.
        findings.append({
            "severity": "HIGH",
            "confidence": "HIGH",
            "test_id": str(item.get("RuleID", "GITLEAKS-UNKNOWN")),
            "language": "Unknown",
            "filename": str(item.get("File", "<unknown-file>")),
            "line_number": item.get("StartLine") if isinstance(item.get("StartLine"), int) else None,
            "description": str(item.get("Description", "Potential hardcoded secret detected."))[:1000],
            "scanner": "Gitleaks",
            "remediation": "Revoke and rotate the exposed credential, then remove it from source history.",
        })
    return findings


def integration_status():
    """Report availability using fixed binary names and bounded version calls."""
    result = {}
    for tool in sorted(TOOLS):
        executable = shutil.which(tool)
        entry = {"available": bool(executable), "version": None}
        if executable:
            try:
                version = subprocess.run([executable, "--version"], capture_output=True,
                                         text=True, timeout=3, check=False)
                entry["version"] = ((version.stdout or version.stderr).strip()[:200] or None)
            except (OSError, subprocess.TimeoutExpired):
                entry["version"] = "unavailable"
        result[tool] = entry
    return result


def _run_json(command, timeout, cwd):
    if timeout < 1 or timeout > 1800:
        raise IntegrationError("Scanner timeout must be between 1 and 1800 seconds.")
    try:
        process = subprocess.Popen(command, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
    except FileNotFoundError:
        raise IntegrationError("Configured scanner is unavailable on PATH.") from None
    except OSError as error:
        raise IntegrationError(f"Scanner could not start ({type(error).__name__}).") from None

    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    limits_exceeded = set()

    def drain(name, stream):
        while True:
            chunk = stream.read(65536)
            if not chunk:
                break
            buffer = buffers[name]
            remaining = MAX_OUTPUT_BYTES + 1 - len(buffer)
            if remaining > 0:
                buffer.extend(chunk[:remaining])
            if len(buffer) > MAX_OUTPUT_BYTES:
                limits_exceeded.add(name)

    readers = [Thread(target=drain, args=(name, getattr(process, name))) for name in ("stdout", "stderr")]
    for reader in readers:
        reader.start()
    try:
        return_code = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        for reader in readers:
            reader.join()
        raise IntegrationError("Scanner execution exceeded its configured timeout.") from None
    for reader in readers:
        reader.join()
    if limits_exceeded:
        raise IntegrationError("Scanner output exceeded the configured output limit.")
    if return_code != 0:
        raise IntegrationError(f"Scanner exited with status {return_code}.")
    try:
        return json.loads(bytes(buffers["stdout"]).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise IntegrationError("Scanner returned invalid JSON output.") from None


def run_optional_scanner(tool, target, timeout=300, semgrep_config=None):
    """Run a selected optional scanner, never through a shell."""
    if tool not in TOOLS - {"trivy"}:
        raise IntegrationError("Choose Semgrep, Bandit, or Gitleaks; Trivy has its dedicated adapter.")
    executable = shutil.which(tool)
    if not executable:
        raise IntegrationError(f"{tool} was not found on PATH; install it explicitly to enable this integration.")
    target_path = Path(target).resolve(strict=True)
    if not target_path.is_dir():
        raise IntegrationError("Scanner target must be an existing directory.")
    if tool == "semgrep":
        config = Path(semgrep_config).resolve(strict=True) if semgrep_config else None
        if not config or not config.is_file():
            raise IntegrationError("Semgrep requires an explicit local rule configuration; automatic rule downloads are disabled.")
        command = [executable, "scan", "--json", "--quiet", "--metrics=off", "--config", str(config), str(target_path)]
        parser = _parse_semgrep
    elif tool == "bandit":
        command = [executable, "-q", "-r", str(target_path), "-f", "json"]
        parser = _parse_bandit
    else:
        command = [executable, "dir", "--no-banner", "--report-format", "json", "--report-path", "-", str(target_path)]
        parser = _parse_gitleaks
    payload = _run_json(command, timeout, str(target_path))
    return parser(payload)
