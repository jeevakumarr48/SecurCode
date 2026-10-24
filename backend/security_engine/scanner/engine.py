import logging
import os
import stat
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
logger = logging.getLogger(__name__)


def scan_file(filename):
    """Scan one supported source file through the language router."""
    return _scan_source_file(str(filename))


def _scan_source_file(filename):
    extension = Path(filename).suffix.lower()
    if extension == ".py":
        return scan_python_file(filename)
    if extension in JAVASCRIPT_EXTENSIONS | TYPESCRIPT_EXTENSIONS:
        return scan_javascript_file(filename)
    return []


def _should_skip_file(filename):
    path = Path(filename)
    return path.suffix.lower() in SKIPPED_SUFFIXES or path.name.endswith((".min.js", ".min.ts", ".bundle.js"))


def _source_files(path, errors):
    if path.is_symlink():
        logger.warning("Symbolic link scan target was not scanned: %s", path)
        errors.append({
            "path": str(path),
            "message": "Symbolic link target was not scanned.",
        })
        return

    path_mode = path.stat().st_mode
    if stat.S_ISREG(path_mode):
        if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
            errors.append({
                "path": str(path),
                "message": "Target file extension is not supported.",
            })
        elif _should_skip_file(path):
            errors.append({
                "path": str(path),
                "message": "Target file is excluded by the scanner policy.",
            })
        else:
            yield path
        return
    if not stat.S_ISDIR(path_mode):
        raise OSError(f"Scan target is not a regular file or directory: {path}")

    def record_walk_error(error):
        errors.append({
            "path": str(error.filename) if error.filename else str(path),
            "message": f"Directory traversal failed ({type(error).__name__}).",
        })
        logger.warning(
            "Unable to traverse source directory %s (%s)",
            error.filename or path,
            type(error).__name__,
        )

    for root, directories, filenames in os.walk(
        path, followlinks=False, onerror=record_walk_error
    ):
        root_path = Path(root)
        traversable_directories = []
        for directory in directories:
            candidate = root_path / directory
            if directory in SKIPPED_DIRECTORIES:
                continue
            if candidate.is_symlink():
                logger.warning("Symbolic link directory was not scanned: %s", candidate)
                errors.append({
                    "path": str(candidate),
                    "message": "Symbolic link directory was not scanned.",
                })
                continue
            traversable_directories.append(directory)
        directories[:] = traversable_directories
        for filename in filenames:
            candidate = root_path / filename
            if candidate.is_symlink():
                if (
                    candidate.suffix.lower() in SUPPORTED_EXTENSIONS
                    and not _should_skip_file(candidate)
                ):
                    logger.warning(
                        "Symbolic link source file was not scanned: %s",
                        candidate,
                    )
                    errors.append({
                        "path": str(candidate),
                        "message": "Symbolic link source file was not scanned.",
                    })
                continue
            if (
                candidate.suffix.lower() in SUPPORTED_EXTENSIONS
                and not _should_skip_file(candidate)
            ):
                yield candidate


def scan_project(path):
    target = Path(path)
    findings = []
    seen = set()
    errors = []
    scanned_files = 0

    try:
        for filename in _source_files(target, errors):
            try:
                file_findings = _scan_source_file(str(filename))
            except Exception as error:
                errors.append({
                    "path": str(filename),
                    "message": f"Source file scan failed ({type(error).__name__}).",
                })
                logger.warning(
                    "Unable to scan source file %s (%s)",
                    filename,
                    type(error).__name__,
                )
                continue

            scanned_files += 1
            for finding in file_findings:
                key = (
                    finding.get("language"),
                    finding.get("test_id"),
                    finding.get("filename"),
                    finding.get("line_number"),
                )
                if key not in seen:
                    seen.add(key)
                    findings.append(finding)
    except OSError as error:
        errors.append({
            "path": str(target),
            "message": f"Source discovery failed ({type(error).__name__}).",
        })
        logger.warning(
            "Unable to discover source files under %s (%s)",
            target,
            type(error).__name__,
        )

    return _scan_result(findings, errors, scanned_files)


def _scan_result(findings, errors, scanned_files):
    status = (
        "completed" if not errors
        else "partial" if scanned_files
        else "failed"
    )
    return {
        "status": status,
        "total_findings": len(findings),
        "findings": findings,
        "errors": errors,
    }
