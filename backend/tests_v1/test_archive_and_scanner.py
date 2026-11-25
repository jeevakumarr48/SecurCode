"""Archive extraction hardening and scanner isolation."""

import io
import stat
import tarfile
import zipfile

import pytest

from app.v1.services.archive import ArchiveError, extract_archive
from app.v1.services.scanning import compute_fingerprint

from .helpers import tar_with, zip_members

LIMITS = dict(max_members=100, max_total_bytes=1_000_000, max_file_bytes=200_000)


@pytest.mark.parametrize("name", ["../escape.py", "a/../../escape.py", "/etc/passwd", "C:/windows/evil.py", "..\\\\evil.py"])
def test_zip_path_traversal_rejected(tmp_path, name):
    with pytest.raises(ArchiveError):
        extract_archive(zip_members({name: b"x"}), tmp_path / "out", **LIMITS)
    assert not (tmp_path / "escape.py").exists()


def test_tar_symlink_and_hardlink_and_device_not_extracted(tmp_path):
    link = tarfile.TarInfo("repo/link.py")
    link.type = tarfile.SYMTYPE
    link.linkname = "/etc/passwd"
    hard = tarfile.TarInfo("repo/hard.py")
    hard.type = tarfile.LNKTYPE
    hard.linkname = "repo/real.py"
    device = tarfile.TarInfo("repo/dev")
    device.type = tarfile.CHRTYPE
    real = tarfile.TarInfo("repo/real.py")
    real.size = 5
    report = extract_archive(tar_with([(real, b"x = 1"), (link, None), (hard, None), (device, None)]), tmp_path / "out", **LIMITS)
    assert report.files == 1
    assert not (tmp_path / "out" / "repo" / "link.py").exists()
    assert not (tmp_path / "out" / "repo" / "hard.py").exists()
    assert len(report.skipped) == 3


def test_zip_symlink_member_skipped(tmp_path):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        info = zipfile.ZipInfo("repo/link.py")
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(info, "/etc/passwd")
    report = extract_archive(buffer.getvalue(), tmp_path / "out", **LIMITS)
    assert report.files == 0 and report.skipped
    assert not (tmp_path / "out" / "repo" / "link.py").exists()


def test_zip_bomb_and_member_limits(tmp_path):
    bomb = io.BytesIO()
    with zipfile.ZipFile(bomb, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("bomb.py", b"0" * 5_000_000)
    with pytest.raises(ArchiveError):
        extract_archive(bomb.getvalue(), tmp_path / "a", **LIMITS)
    many = zip_members({f"f{i}.py": b"x" for i in range(150)})
    with pytest.raises(ArchiveError, match="more than 100"):
        extract_archive(many, tmp_path / "b", **LIMITS)


def test_duplicate_members_rejected(tmp_path):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("a.py", b"1")
        archive.writestr("A.py", b"2")
    with pytest.raises(ArchiveError, match="duplicate"):
        extract_archive(buffer.getvalue(), tmp_path / "out", **LIMITS)


def test_unknown_format_rejected(tmp_path):
    with pytest.raises(ArchiveError, match="Unsupported"):
        extract_archive(b"MZ\x90\x00 not an archive", tmp_path / "out", **LIMITS)


def test_fingerprint_stable_across_line_moves_and_whitespace():
    a = compute_fingerprint("PYSEC012", "app/x.py", "    digest = hashlib.md5(data)", 0)
    b = compute_fingerprint("PYSEC012", "app/x.py", "digest  =  hashlib.md5(data)", 0)
    c = compute_fingerprint("PYSEC012", "app/y.py", "digest = hashlib.md5(data)", 0)
    d = compute_fingerprint("PYSEC012", "app/x.py", "digest = hashlib.md5(data)", 1)
    assert a == b and a != c and a != d


def test_scanner_subprocess_has_no_secrets_and_never_imports_scanned_code(tmp_path, monkeypatch):
    """A planted module in the scanned tree must never be imported/executed."""
    from app.v1.services.policy import DEFAULT_POLICY
    from app.v1.services.scanning import run_isolated_scan

    marker = tmp_path / "PWNED"
    (tmp_path / "src").mkdir()
    for name in ("json.py", "security_engine.py", "sitecustomize.py", "re.py"):
        (tmp_path / "src" / name).write_text(f"open({str(marker)!r}, 'w').write('x')\n")
    (tmp_path / "src" / "app.py").write_text("eval(user_input)\n")
    monkeypatch.setenv("SECURCODE_SMTP_PASSWORD", "super-secret")
    result = run_isolated_scan(tmp_path / "src", DEFAULT_POLICY)
    assert not marker.exists()
    assert any(f["rule_id"] == "SEC001" for f in result["findings"])


def test_benchmark_v2_has_no_false_results():
    from security_engine.benchmark_v2 import run

    report = run()
    assert report["false_positives"] == 0 and report["false_negatives"] == 0
    assert report["true_positives"] >= 40
