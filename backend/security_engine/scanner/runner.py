"""Combined scan of a directory: original engine rules + extended rules.

Intended to run inside an isolated, resource-limited child process
(see app.v1.worker). It only *reads* files as text; nothing is executed,
imported or installed from the scanned tree.

Usage: python -I -m security_engine.scanner.runner <directory> < config.json > result.json
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from types import SimpleNamespace

from . import engine
from .extended import scan_extended
from .rules import RULES, SCANNER_VERSION, ruleset_version


def scan_directory(root: str, limits: dict | None = None) -> dict:
    limits = limits or {}
    base = Path(root).resolve()
    original_settings = engine.settings
    engine.settings = SimpleNamespace(
        max_scan_files=int(limits.get("max_files", 5000)),
        max_scan_depth=int(limits.get("max_depth", 30)),
        max_scan_seconds=int(limits.get("max_seconds", 120)),
        max_source_file_bytes=int(limits.get("max_file_bytes", 2_000_000)),
        max_scan_bytes=int(limits.get("max_total_bytes", 200_000_000)),
    )
    started = time.monotonic()
    try:
        core = engine.scan_project(str(base))
        discovery_errors: list[dict] = []
        files = []
        languages: dict[str, int] = {}
        for path in engine._source_files(base, discovery_errors):
            if len(files) >= engine.settings.max_scan_files:
                break
            try:
                if path.stat().st_size > engine.settings.max_source_file_bytes:
                    continue
            except OSError:
                continue
            files.append(path)
        extended: list[dict] = []
        errors = list(core["errors"])
        for path in files:
            if time.monotonic() - started > engine.settings.max_scan_seconds:
                errors.append({"path": str(path), "message": "Extended rules stopped at the scan time limit."})
                break
            suffix = path.suffix.lower()
            language = "python" if suffix == ".py" else "typescript" if suffix in {".ts", ".tsx"} else "javascript"
            languages[language] = languages.get(language, 0) + 1
            try:
                extended.extend(scan_extended(str(path)))
            except Exception as error:  # noqa: BLE001 - one bad file must not abort the scan
                errors.append({"path": str(path), "message": f"Extended rules failed ({type(error).__name__})."})
    finally:
        engine.settings = original_settings

    findings = []
    seen = set()
    for item in [*core["findings"], *extended]:
        try:
            relative = Path(item["filename"]).resolve().relative_to(base).as_posix()
        except (ValueError, OSError):
            continue
        key = (item["test_id"], relative, item.get("line_number"), item.get("column_number"))
        if key in seen:
            continue
        seen.add(key)
        rule = RULES.get(item["test_id"])
        findings.append({
            "rule_id": item["test_id"],
            # The registry is the single source of truth for severity.
            "severity": rule.severity if rule else (item.get("severity") or "medium").lower(),
            "confidence": (item.get("confidence") or (rule.confidence if rule else "medium")).lower(),
            "language": item.get("language"),
            "file_path": relative,
            "line": item.get("line_number"),
            "column": item.get("column_number"),
            "description": item.get("description") or (rule.description if rule else ""),
            "cwe": item.get("cwe") or (rule.cwe if rule else None),
        })
    for error in errors:
        try:
            error["path"] = Path(error["path"]).resolve().relative_to(base).as_posix()
        except (ValueError, OSError, KeyError):
            error["path"] = "."
    return {
        "status": core["status"] if core["status"] != "completed" or not errors else "partial",
        "scanner_version": SCANNER_VERSION,
        "ruleset_version": ruleset_version(),
        "rule_ids": sorted(RULES),
        "files_scanned": len(files),
        "languages": languages,
        "findings": findings,
        "errors": errors,
        "duration_ms": int((time.monotonic() - started) * 1000),
    }


def main() -> int:  # pragma: no cover - exercised through the worker subprocess
    if len(sys.argv) != 2:
        print(json.dumps({"fatal": "usage: runner <directory>"}))
        return 2
    limits = json.loads(sys.stdin.read() or "{}")
    result = scan_directory(sys.argv[1], limits)
    sys.stdout.write(json.dumps(result))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
