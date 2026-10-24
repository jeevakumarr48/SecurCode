import os
from pathlib import Path

from .javascript import (
    JAVASCRIPT_EXTENSIONS,
    TYPESCRIPT_EXTENSIONS,
    scan_javascript_file,
)
from .python import scan_python_file


SUPPORTED_EXTENSIONS = {".py", *JAVASCRIPT_EXTENSIONS, *TYPESCRIPT_EXTENSIONS}
SKIPPED_DIRECTORIES = {
    ".git",
    ".hg",
    ".mypy_cache",
    ".next",
    ".pytest_cache",
    ".venv",
    ".tox",
    ".cache",
    "__pycache__",
    "build",
    "coverage",
    "dist",
    "env",
    "node_modules",
    "out",
    "site-packages",
    "target",
    "venv",
    "vendor",
}
SKIPPED_SUFFIXES = {".map"}


def scan_file(filename, strict=False):
    """Scan one supported source file through the language router."""
    return _scan_source_file(str(filename), strict=strict)


def _scan_source_file(filename, strict=False):
    extension = Path(filename).suffix.lower()
    if extension == ".py":
        return scan_python_file(filename, strict=strict)
    if extension in JAVASCRIPT_EXTENSIONS | TYPESCRIPT_EXTENSIONS:
        return scan_javascript_file(filename, strict=strict)
    return []


def _should_skip_file(filename):
    path = Path(filename)
    return path.suffix.lower() in SKIPPED_SUFFIXES or path.name.endswith((".min.js", ".min.ts", ".bundle.js"))


def _source_files(path):
    if path.is_file():
        if path.suffix.lower() in SUPPORTED_EXTENSIONS and not _should_skip_file(path):
            yield path
        return

    for root, directories, filenames in os.walk(path, followlinks=False, onerror=lambda _error: None):
        root_path = Path(root)
        directories[:] = [
            directory
            for directory in directories
            if directory not in SKIPPED_DIRECTORIES
            and not (root_path / directory).is_symlink()
        ]
        for filename in filenames:
            candidate = root_path / filename
            if (
                not candidate.is_symlink()
                and candidate.suffix.lower() in SUPPORTED_EXTENSIONS
                and not _should_skip_file(candidate)
            ):
                yield candidate


def scan_project(path):
    target = Path(path)
    findings = []
    seen = set()

    if not target.exists():
        return {"status": "completed", "total_findings": 0, "findings": []}

    for filename in _source_files(target):
        for finding in _scan_source_file(str(filename)):
            key = (
                finding.get("language"),
                finding.get("test_id"),
                finding.get("filename"),
                finding.get("line_number"),
            )
            if key not in seen:
                seen.add(key)
                findings.append(finding)
    return {
        "status": "completed",
        "total_findings": len(findings),
        "findings": findings,
    }
