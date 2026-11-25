"""Scan execution: source preparation, isolated analysis, persistence and
finding lifecycle reconciliation."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from collections import Counter
from datetime import timedelta
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from security_engine.scanner.rules import RULES, SCANNER_VERSION, ruleset_version

from .. import audit
from ..db import SessionLocal, utcnow
from ..models import Finding, FindingEvent, Integration, Project, Scan, ScanFinding, SourceArchive
from ..security import redact_snippet
from ..settings import platform_settings
from .archive import ArchiveError, extract_archive, single_top_level_directory
from .common import notify, org_members_with_roles
from .policy import confidence_at_least, effective_policy, path_excluded, severity_at_least

logger = logging.getLogger("securcode.v1.scan")
BACKEND_DIR = Path(__file__).resolve().parents[3]
FIXTURE_ROOT = BACKEND_DIR.parent / "scanner-fixtures" / "projects"
ACTIVE_STATUSES = {"open", "triaged", "in_progress", "fixed", "reopened"}
MAX_FINDINGS_PER_SCAN = 20_000
MAX_RESULT_BYTES = 50_000_000


class ScanCancelled(Exception):
    pass


class ScanFailure(Exception):
    """A failure whose message is safe to show to the scan's requester."""


def available_fixtures() -> list[str]:
    if not FIXTURE_ROOT.is_dir():
        return []
    return sorted(p.name for p in FIXTURE_ROOT.iterdir() if p.is_dir() and not p.is_symlink() and re.fullmatch(r"[a-z0-9-]{1,60}", p.name))


def scope_key_for(source_type: str, branch: str | None, pull_request_number: int | None) -> str:
    if pull_request_number:
        return f"pr:{pull_request_number}"
    if source_type == "github" and branch:
        return f"branch:{branch}"[:250]
    return "default"


def _log(scan: Scan, message: str, level: str = "info") -> None:
    entry = {"at": utcnow().isoformat(), "level": level, "message": message[:500]}
    scan.logs = [*scan.logs[-199:], entry]


def _progress(db: Session, scan: Scan, percent: int, message: str) -> None:
    scan.progress = percent
    scan.progress_message = message[:200]
    _log(scan, message)
    db.commit()
    db.refresh(scan)
    if scan.cancel_requested:
        raise ScanCancelled()


# --- Source preparation -------------------------------------------------------------

def _prepare_source(db: Session, scan: Scan, project: Project, workspace: Path, policy: dict) -> Path:
    limits = dict(
        max_members=platform_settings.max_archive_members,
        max_total_bytes=platform_settings.max_extracted_bytes,
        max_file_bytes=policy["max_file_bytes"],
    )
    source_dir = workspace / "src"
    if scan.source_type == "upload":
        archive = db.get(SourceArchive, scan.archive_id) if scan.archive_id else None
        if archive is None or archive.org_id != scan.org_id or archive.project_id != scan.project_id:
            raise ScanFailure("The uploaded source archive is no longer available.")
        try:
            report = extract_archive(archive.content, source_dir, **limits)
        except ArchiveError as error:
            raise ScanFailure(f"Archive rejected: {error}") from None
        for skipped in report.skipped[:50]:
            scan.warnings = [*scan.warnings, {"path": skipped.split(":", 1)[0], "message": skipped.split(":", 1)[-1].strip()}]
        return single_top_level_directory(source_dir)
    if scan.source_type == "fixture":
        name = project.fixture_name or ""
        if name not in available_fixtures():
            raise ScanFailure("The configured test fixture does not exist.")
        shutil.copytree(FIXTURE_ROOT / name, source_dir, symlinks=True, ignore_dangling_symlinks=True,
                        ignore=lambda directory, names: [n for n in names if os.path.islink(os.path.join(directory, n))])
        return source_dir
    if scan.source_type == "github":
        from .github import GitHubError, download_repository_archive

        integration = db.get(Integration, project.integration_id) if project.integration_id else None
        if integration is None or integration.org_id != scan.org_id or integration.status == "revoked":
            raise ScanFailure("The project's GitHub integration is missing or revoked.")
        try:
            data, commit_sha = download_repository_archive(
                integration, project.repository_full_name, scan.commit_sha or scan.branch or project.default_branch,
                max_bytes=policy["max_archive_bytes"],
            )
        except GitHubError as error:
            integration.status = "error" if error.credential_problem else integration.status
            integration.last_error = str(error)[:500]
            raise ScanFailure(f"GitHub download failed: {error}") from None
        scan.commit_sha = commit_sha
        try:
            report = extract_archive(data, source_dir, **limits)
        except ArchiveError as error:
            raise ScanFailure(f"Repository archive rejected: {error}") from None
        for skipped in report.skipped[:50]:
            scan.warnings = [*scan.warnings, {"path": skipped.split(":", 1)[0], "message": skipped.split(":", 1)[-1].strip()}]
        return single_top_level_directory(source_dir)
    raise ScanFailure("Unsupported scan source type.")


# --- Isolated analysis ----------------------------------------------------------

def _limit_resources():  # pragma: no cover - runs in the child process
    import resource

    memory = platform_settings.scan_memory_mb * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
    cpu = platform_settings.scan_timeout_seconds + 5
    resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
    resource.setrlimit(resource.RLIMIT_FSIZE, (10 * 1024 * 1024, 10 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.setsid()


def run_isolated_scan(source_dir: Path, policy: dict, should_cancel=lambda: False) -> dict:
    """Run the analyser in a separate, resource-limited Python process.

    The child is started with ``-I`` (isolated mode: no PYTHONPATH, no user
    site-packages, no current-directory imports) from an empty working
    directory, with a minimal environment that contains no secrets.
    """
    timeout = min(platform_settings.scan_timeout_seconds, policy["max_scan_seconds"])
    limits = {
        "max_files": 20_000,
        "max_depth": 40,
        "max_seconds": max(timeout - 5, 5),
        "max_file_bytes": policy["max_file_bytes"],
        "max_total_bytes": platform_settings.max_extracted_bytes,
    }
    bootstrap = (
        "import sys; sys.path.insert(0, sys.argv[2]); "
        "sys.argv = [sys.argv[0], sys.argv[1]]; "
        "from security_engine.scanner.runner import main; raise SystemExit(main())"
    )
    env = {"PATH": os.environ.get("PATH", ""), "LANG": "C.UTF-8", "PYTHONHASHSEED": "0", "SECURCODE_ENV": "test"}
    if os.name == "nt":  # pragma: no cover - Windows needs SYSTEMROOT for Python to start
        env["SYSTEMROOT"] = os.environ.get("SYSTEMROOT", "C:\\Windows")
    with tempfile.TemporaryDirectory(prefix="sc-runner-cwd-") as empty_cwd:
        process = subprocess.Popen(
            [sys.executable, "-I", "-c", bootstrap, str(source_dir), str(BACKEND_DIR)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=empty_cwd, env=env,
            preexec_fn=_limit_resources if os.name == "posix" else None,
        )
        payload = json.dumps(limits).encode()
        deadline = time.monotonic() + timeout
        stdout = stderr = b""
        first = True
        while True:
            try:
                stdout, stderr = process.communicate(input=payload if first else None, timeout=2)
                break
            except subprocess.TimeoutExpired:
                first = False
                if should_cancel():
                    _kill(process)
                    raise ScanCancelled() from None
                if time.monotonic() > deadline:
                    _kill(process)
                    raise ScanFailure(f"Analysis exceeded the {timeout}-second scan time limit.") from None
    if process.returncode != 0:
        if process.returncode in (-signal.SIGKILL, -signal.SIGXCPU) if os.name == "posix" else False:
            raise ScanFailure("Analysis exceeded its CPU or memory limit.")
        logger.warning("Scanner process failed (exit %s): %s", process.returncode, stderr[-500:].decode(errors="replace"))
        raise ScanFailure("The analysis process failed unexpectedly.")
    if len(stdout) > MAX_RESULT_BYTES:
        raise ScanFailure("The scan produced more results than can be stored.")
    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        raise ScanFailure("The analysis process returned an unreadable result.") from None


def _kill(process: subprocess.Popen) -> None:
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:  # pragma: no cover
            process.kill()
    except (ProcessLookupError, PermissionError):
        pass
    process.communicate()


# --- Fingerprinting -------------------------------------------------------------

def _normalise_line(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def compute_fingerprint(rule_id: str, file_path: str, line_text: str, occurrence: int) -> str:
    """Stable identity that survives line moves.

    Combines rule, file path, whitespace-normalised source line content and the
    occurrence index of identical (rule, path, content) tuples. It does not
    survive file renames or edits to the flagged line itself.
    """
    material = f"{rule_id}\x1f{file_path}\x1f{_normalise_line(line_text)}\x1f{occurrence}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _read_context(source_dir: Path, relative: str, line: int | None) -> tuple[str, str]:
    path = (source_dir / relative).resolve()
    if source_dir.resolve() not in path.parents or path.is_symlink():
        return "", ""
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return "", ""
    if not line or line < 1 or line > len(lines):
        return "", ""
    start, end = max(line - 3, 0), min(line + 2, len(lines))
    context = "\n".join(f"{number + 1:>5} | {lines[number][:240]}" for number in range(start, end))
    return lines[line - 1], context


# --- Persistence and lifecycle -----------------------------------------------------

def _event(db: Session, finding: Finding, kind: str, body: str, from_value=None, to_value=None, actor_id=None) -> None:
    db.add(FindingEvent(org_id=finding.org_id, finding_id=finding.id, actor_id=actor_id, kind=kind, body=body,
                        from_value=from_value, to_value=to_value))


def persist_results(db: Session, scan: Scan, project: Project, result: dict, source_dir: Path, policy: dict) -> dict:
    now = utcnow()
    disabled = set(policy["disabled_rules"])
    ran_rules = sorted(set(result.get("rule_ids", [])) - disabled)
    scan.rule_ids = ran_rules
    scan.scanner_version = result.get("scanner_version", SCANNER_VERSION)
    scan.ruleset_version = result.get("ruleset_version", ruleset_version())
    scan.files_scanned = int(result.get("files_scanned", 0))
    warnings = list(scan.warnings) + [
        {"path": e.get("path", "."), "message": e.get("message", "")} for e in result.get("errors", [])[:200]
    ]
    raw = result.get("findings", [])
    if len(raw) > MAX_FINDINGS_PER_SCAN:
        warnings.append({"path": ".", "message": f"Only the first {MAX_FINDINGS_PER_SCAN} findings were stored."})
        raw = raw[:MAX_FINDINGS_PER_SCAN]
    filtered_out = 0
    occurrences: Counter = Counter()
    candidates = []
    for item in sorted(raw, key=lambda f: (f["file_path"], f.get("line") or 0, f["rule_id"], f.get("column") or 0)):
        if item["rule_id"] in disabled or path_excluded(item["file_path"], policy["excluded_paths"]):
            filtered_out += 1
            continue
        if not severity_at_least(item["severity"], policy["minimum_severity"]) or not confidence_at_least(item["confidence"], policy["minimum_confidence"]):
            filtered_out += 1
            continue
        line_text, context = _read_context(source_dir, item["file_path"], item.get("line"))
        key = (item["rule_id"], item["file_path"], _normalise_line(line_text))
        occurrence = occurrences[key]
        occurrences[key] += 1
        candidates.append((item, compute_fingerprint(item["rule_id"], item["file_path"], line_text, occurrence), context))

    existing = {
        f.fingerprint: f
        for f in db.execute(
            select(Finding).where(Finding.project_id == project.id, Finding.scope_key == scan.scope_key)
        ).scalars()
    }
    seen_ids: set[str] = set()
    new_findings: list[Finding] = []
    reopened = 0
    for item, fingerprint, context in candidates:
        rule = RULES.get(item["rule_id"])
        finding = existing.get(fingerprint)
        if finding is None:
            due_days = policy["default_due_days"].get(item["severity"])
            finding = Finding(
                org_id=scan.org_id, project_id=project.id, scope_key=scan.scope_key, fingerprint=fingerprint,
                rule_id=item["rule_id"], title=(rule.name if rule else item["rule_id"])[:200],
                description=item.get("description", "")[:4000], severity=item["severity"], original_severity=item["severity"],
                confidence=item["confidence"], language=item.get("language"), cwe=item.get("cwe"),
                owasp=(rule.as_dict()["owasp"] if rule else None), file_path=item["file_path"][:1000], line=item.get("line"),
                snippet=redact_snippet(context, 1200), remediation=rule.remediation if rule else None,
                status="open", first_detected_at=now, last_detected_at=now, first_scan_id=scan.id, last_scan_id=scan.id,
                due_date=now + timedelta(days=due_days) if due_days else None,
            )
            db.add(finding)
            db.flush()
            existing[fingerprint] = finding
            new_findings.append(finding)
            _event(db, finding, "system", f"First detected by scan {scan.id[:8]}.")
        else:
            if finding.id in seen_ids:
                continue
            finding.last_detected_at = now
            finding.last_scan_id = scan.id
            finding.line = item.get("line")
            finding.snippet = redact_snippet(context, 1200)
            finding.confidence = item["confidence"]
            if finding.severity == finding.original_severity:
                finding.severity = item["severity"]
            finding.original_severity = item["severity"]
            if finding.status in {"resolved"} or (finding.status == "fixed" and finding.verification_status == "verified_fixed"):
                previous = finding.status
                finding.status = "reopened"
                finding.verification_status = "unverified"
                finding.recurrence_count += 1
                finding.fixed_scan_id = None
                reopened += 1
                _event(db, finding, "status", f"Detected again by scan {scan.id[:8]}; reopened as a recurrence.", previous, "reopened")
            elif finding.status == "fixed":
                finding.verification_status = "still_present"
                _event(db, finding, "verification", f"Marked fixed but still detected by scan {scan.id[:8]}.")
        seen_ids.add(finding.id)
        db.add(ScanFinding(org_id=scan.org_id, scan_id=scan.id, finding_id=finding.id, fingerprint=fingerprint,
                           rule_id=finding.rule_id, severity=item["severity"], confidence=item["confidence"],
                           file_path=finding.file_path, line=item.get("line")))

    complete = not warnings and scan.files_scanned > 0
    resolved = 0
    unverified = 0
    for finding in existing.values():
        if finding.id in seen_ids:
            continue
        in_scope = finding.rule_id in ran_rules and not path_excluded(finding.file_path, policy["excluded_paths"])
        if finding.status in ACTIVE_STATUSES:
            if complete and in_scope:
                previous = finding.status
                finding.status = "resolved"
                finding.verification_status = "verified_fixed"
                finding.fixed_scan_id = scan.id
                resolved += 1
                _event(db, finding, "verification",
                       f"Not detected by complete scan {scan.id[:8]} under rule {finding.rule_id}; verified fixed.",
                       previous, "resolved")
            else:
                unverified += 1
        elif finding.status in {"accepted_risk", "false_positive"} and complete and in_scope:
            finding.verification_status = "not_detected"

    if scan.files_scanned == 0:
        warnings.append({"path": ".", "message": "No supported source files were found; this is not a clean result."})
    scan.warnings = warnings[:300]
    severity_counts = Counter(item["severity"] for item, _, _ in candidates)
    scan.summary = {
        "total": len(candidates),
        "by_severity": dict(severity_counts),
        "new": len(new_findings),
        "reopened": reopened,
        "resolved": resolved,
        "not_verified_due_to_partial_scan": unverified if not complete else 0,
        "filtered_by_policy": filtered_out,
        "languages": result.get("languages", {}),
    }
    project.languages = sorted(result.get("languages", {}))
    project.last_scan_at = now
    return {"new": new_findings, "complete": complete}


def execute_scan(scan_id: str, worker_id: str = "inline") -> str:
    """Run one claimed scan end to end. Returns the final status."""
    db = SessionLocal()
    workspace = Path(tempfile.mkdtemp(prefix="sc-scan-", dir=os.getenv("SECURCODE_SCAN_WORKDIR") or None))
    started = time.monotonic()
    try:
        scan = db.get(Scan, scan_id)
        if scan is None or scan.status != "running":
            return scan.status if scan else "missing"
        project = db.get(Project, scan.project_id)
        if project is None or project.org_id != scan.org_id:
            raise ScanFailure("Scan ownership could not be validated.")
        policy = effective_policy(db, scan.org_id)
        scan.config_json = {**scan.config_json, "policy": {k: policy[k] for k in (
            "minimum_severity", "minimum_confidence", "excluded_paths", "max_file_bytes", "max_scan_seconds")},
            "disabled_rules": sorted(policy["disabled_rules"])}
        _progress(db, scan, 10, "Preparing isolated workspace")
        source_dir = _prepare_source(db, scan, project, workspace, policy)
        _progress(db, scan, 30, "Analysing source code")

        def cancelled() -> bool:
            with SessionLocal() as check:
                return bool(check.execute(select(Scan.cancel_requested).where(Scan.id == scan_id)).scalar())

        result = run_isolated_scan(source_dir, policy, cancelled)
        _progress(db, scan, 80, f"Recording {len(result.get('findings', []))} raw results")
        outcome = persist_results(db, scan, project, result, source_dir, policy)
        scan.status = "completed" if outcome["complete"] else "completed_with_warnings"
        scan.progress = 100
        scan.progress_message = "Completed" if outcome["complete"] else "Completed with warnings"
        _log(scan, scan.progress_message)
        _finish(db, scan, started)
        _after_completion(db, scan, project, outcome["new"])
        db.commit()
        return scan.status
    except ScanCancelled:
        db.rollback()
        scan = db.get(Scan, scan_id)
        scan.status = "cancelled"
        scan.progress_message = "Cancelled"
        _log(scan, "Scan cancelled on request.", "warning")
        _finish(db, scan, started)
        db.commit()
        return "cancelled"
    except ScanFailure as error:
        db.rollback()
        return _fail(db, scan_id, str(error), started)
    except Exception as error:  # noqa: BLE001 - never leave a scan stuck in running
        logger.exception("Unexpected scan failure (%s)", type(error).__name__)
        db.rollback()
        return _fail(db, scan_id, "An internal error stopped the scan.", started)
    finally:
        shutil.rmtree(workspace, ignore_errors=True)
        db.close()


def _finish(db: Session, scan: Scan, started: float) -> None:
    scan.finished_at = utcnow()
    scan.duration_ms = int((time.monotonic() - started) * 1000)
    scan.lease_owner = None
    scan.lease_expires_at = None


def _fail(db: Session, scan_id: str, message: str, started: float) -> str:
    scan = db.get(Scan, scan_id)
    if scan is None:
        return "missing"
    scan.status = "failed"
    scan.error_message = message[:1000]
    scan.progress_message = "Failed"
    _log(scan, message, "error")
    _finish(db, scan, started)
    project = db.get(Project, scan.project_id)
    recipients = {scan.requested_by_id, project.owner_id if project else None}
    notify(db, recipients, "scan_failed", f"Scan failed: {project.name if project else 'project'}", message,
           f"/orgs/{scan.org_id}/scans/{scan.id}", scan.org_id)
    audit.record(db, "scan.failed", org_id=scan.org_id, project_id=scan.project_id, resource_type="scan",
                 resource_id=scan.id, metadata={"reason": message[:200]})
    db.commit()
    return "failed"


def _after_completion(db: Session, scan: Scan, project: Project, new_findings: list[Finding]) -> None:
    link = f"/orgs/{scan.org_id}/scans/{scan.id}"
    summary = scan.summary
    notify(db, {scan.requested_by_id, project.owner_id}, "scan_completed",
           f"Scan {scan.status.replace('_', ' ')}: {project.name}",
           f"{summary['total']} findings ({summary['new']} new, {summary['resolved']} resolved).", link, scan.org_id)
    critical = [f for f in new_findings if f.severity == "critical"]
    high = [f for f in new_findings if f.severity == "high"]
    security_team = org_members_with_roles(db, scan.org_id, {"owner", "admin", "security_admin"})
    if critical:
        notify(db, security_team, "critical_finding", f"{len(critical)} new critical finding(s) in {project.name}",
               critical[0].title, link, scan.org_id)
    if high:
        notify(db, security_team, "high_finding", f"{len(high)} new high finding(s) in {project.name}", high[0].title, link, scan.org_id)
    audit.record(db, "scan.completed", org_id=scan.org_id, project_id=project.id, resource_type="scan", resource_id=scan.id,
                 metadata={"status": scan.status, **{k: summary[k] for k in ("total", "new", "resolved", "reopened")}})
    if scan.pull_request_number:
        from .github import publish_pull_request_result

        policy = effective_policy(db, scan.org_id)
        outcome = publish_pull_request_result(db, scan, policy.get("pr_fail_severity"))
        if outcome is not None:
            scan.summary = {**scan.summary, "pull_request_publish": outcome}
