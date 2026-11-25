"""Defensive extraction of untrusted source archives.

Threats handled: path traversal (``../``, absolute and drive paths), symlink
and hardlink members, device files, zip bombs (member count, total and
per-file uncompressed size, compression ratio), duplicate members, and
non-UTF-8 trickery in names. Nothing extracted is ever executed.
"""

from __future__ import annotations

import io
import os
import stat
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

ZIP_MAGIC = (b"PK\x03\x04", b"PK\x05\x06")
GZIP_MAGIC = b"\x1f\x8b"
MAX_RATIO = 200  # uncompressed / compressed per member
MAX_NAME_LENGTH = 400
MAX_DEPTH = 40


class ArchiveError(ValueError):
    """Raised for archives that are unsafe or exceed configured limits."""


@dataclass
class ExtractionReport:
    files: int = 0
    bytes: int = 0
    skipped: list[str] = field(default_factory=list)


def detect_format(data: bytes) -> str:
    if data.startswith(ZIP_MAGIC):
        return "zip"
    if data.startswith(GZIP_MAGIC):
        return "tar.gz"
    if len(data) > 262 and data[257:262] == b"ustar":
        return "tar"
    raise ArchiveError("Unsupported archive format. Upload a .zip, .tar.gz or .tgz file.")


def _safe_relative(name: str) -> PurePosixPath:
    if not name or len(name) > MAX_NAME_LENGTH or "\x00" in name:
        raise ArchiveError("Archive contains an invalid member name.")
    normalised = name.replace("\\", "/")
    if normalised.startswith("/") or (len(normalised) > 1 and normalised[1] == ":"):
        raise ArchiveError("Archive contains an absolute path.")
    path = PurePosixPath(normalised)
    parts = [part for part in path.parts if part not in ("", ".")]
    if any(part == ".." for part in parts):
        raise ArchiveError("Archive contains a path-traversal entry.")
    if len(parts) > MAX_DEPTH:
        raise ArchiveError("Archive nesting is too deep.")
    return PurePosixPath(*parts) if parts else PurePosixPath(".")


def _target(root: Path, relative: PurePosixPath) -> Path:
    target = (root / Path(*relative.parts)).resolve()
    root_resolved = root.resolve()
    if target != root_resolved and root_resolved not in target.parents:
        raise ArchiveError("Archive member resolves outside the workspace.")
    return target


def _write(target: Path, source, limit_remaining: int, per_file_limit: int) -> int:
    target.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    written = 0
    fd = os.open(target, flags, 0o600)
    with os.fdopen(fd, "wb") as handle:
        while True:
            chunk = source.read(65536)
            if not chunk:
                break
            written += len(chunk)
            if written > per_file_limit or written > limit_remaining:
                raise ArchiveError("Archive expands beyond the configured size limits.")
            handle.write(chunk)
    return written


def extract_archive(
    data: bytes,
    destination: Path,
    *,
    max_members: int,
    max_total_bytes: int,
    max_file_bytes: int,
) -> ExtractionReport:
    destination.mkdir(parents=True, exist_ok=True)
    archive_format = detect_format(data)
    report = ExtractionReport()
    seen: set[str] = set()
    if archive_format == "zip":
        try:
            archive = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile as error:
            raise ArchiveError("The zip archive is corrupt.") from error
        with archive:
            members = archive.infolist()
            if len(members) > max_members:
                raise ArchiveError(f"Archive contains more than {max_members} entries.")
            declared = sum(m.file_size for m in members)
            if declared > max_total_bytes:
                raise ArchiveError("Archive expands beyond the configured size limits.")
            for member in members:
                relative = _safe_relative(member.filename)
                mode = (member.external_attr >> 16) & 0xFFFF
                if stat.S_ISLNK(mode):
                    report.skipped.append(f"{relative}: symbolic link not extracted")
                    continue
                if member.is_dir() or str(relative) == ".":
                    _target(destination, relative).mkdir(parents=True, exist_ok=True)
                    continue
                if member.flag_bits & 0x1:
                    raise ArchiveError("Encrypted archive members are not supported.")
                key = str(relative).lower()
                if key in seen:
                    raise ArchiveError("Archive contains duplicate member names.")
                seen.add(key)
                if member.file_size > max_file_bytes:
                    report.skipped.append(f"{relative}: exceeds per-file size limit")
                    continue
                if member.compress_size and member.file_size / max(member.compress_size, 1) > MAX_RATIO and member.file_size > 1_000_000:
                    raise ArchiveError("Archive member has a suspicious compression ratio.")
                target = _target(destination, relative)
                with archive.open(member) as source:
                    report.bytes += _write(target, source, max_total_bytes - report.bytes, max_file_bytes)
                report.files += 1
        return report

    mode = "r:gz" if archive_format == "tar.gz" else "r:"
    try:
        archive = tarfile.open(fileobj=io.BytesIO(data), mode=mode)
    except (tarfile.TarError, OSError, EOFError) as error:
        raise ArchiveError("The tar archive is corrupt.") from error
    with archive:
        count = 0
        while True:
            try:
                member = archive.next()
            except (tarfile.TarError, OSError, EOFError) as error:
                raise ArchiveError("The tar archive is corrupt.") from error
            if member is None:
                break
            count += 1
            if count > max_members:
                raise ArchiveError(f"Archive contains more than {max_members} entries.")
            relative = _safe_relative(member.name)
            if member.issym() or member.islnk():
                report.skipped.append(f"{relative}: link not extracted")
                continue
            if member.isdir() or str(relative) == ".":
                _target(destination, relative).mkdir(parents=True, exist_ok=True)
                continue
            if not member.isreg():
                report.skipped.append(f"{relative}: special file not extracted")
                continue
            key = str(relative).lower()
            if key in seen:
                raise ArchiveError("Archive contains duplicate member names.")
            seen.add(key)
            if member.size > max_file_bytes:
                report.skipped.append(f"{relative}: exceeds per-file size limit")
                continue
            if report.bytes + member.size > max_total_bytes:
                raise ArchiveError("Archive expands beyond the configured size limits.")
            source = archive.extractfile(member)
            if source is None:
                continue
            with source:
                report.bytes += _write(_target(destination, relative), source, max_total_bytes - report.bytes, max_file_bytes)
            report.files += 1
    return report


def single_top_level_directory(root: Path) -> Path:
    """GitHub tarballs wrap content in one ``owner-repo-sha/`` directory."""
    entries = [entry for entry in root.iterdir()]
    if len(entries) == 1 and entries[0].is_dir() and not entries[0].is_symlink():
        return entries[0]
    return root
