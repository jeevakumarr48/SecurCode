from pathlib import Path
from threading import Event

import security_engine.scanner.watcher as watcher_module
from security_engine.scanner.watcher import SourceFileWatcher


def test_watcher_reports_file_modifications_and_clears_stale_findings(tmp_path):
    source = tmp_path / "watched.py"
    source.write_text("value = 1\n", encoding="utf-8")
    updates = []
    update_received = Event()

    def on_change(filename, findings):
        updates.append((filename, findings))
        update_received.set()

    watcher = SourceFileWatcher(
        root=tmp_path,
        on_change=on_change,
        interval=0.2,
        debounce=0.1,
    )
    watcher.start()

    try:
        source.write_text("eval(input)\n", encoding="utf-8")
        assert update_received.wait(timeout=3)

        changed_file, findings = updates[-1]
        assert changed_file == source
        assert [finding["test_id"] for finding in findings] == ["SEC001"]

        update_received.clear()
        source.write_text("value = 1\n", encoding="utf-8")
        assert update_received.wait(timeout=3)

        changed_file, findings = updates[-1]
        assert changed_file == source
        assert findings == []
    finally:
        watcher.stop()


def test_watcher_reports_scan_error_without_clean_update(monkeypatch, tmp_path):
    source = tmp_path / "invalid.py"
    source.write_text("def broken(:\n", encoding="utf-8")
    updates = []
    errors = []
    watcher = SourceFileWatcher(
        root=tmp_path,
        on_change=lambda filename, findings: updates.append((filename, findings)),
        on_error=lambda filename, error: errors.append((filename, error)),
    )
    def fail_scan(*_args, **_kwargs):
        raise SyntaxError("invalid")

    monkeypatch.setattr(watcher_module, "scan_file", fail_scan)

    watcher._scan_and_notify(source)

    assert updates == []
    assert errors[0][0] == source
    assert isinstance(errors[0][1], SyntaxError)


def test_watcher_contains_unexpected_scan_errors(monkeypatch, tmp_path):
    source = tmp_path / "unexpected.py"
    updates = []
    errors = []
    watcher = SourceFileWatcher(
        root=tmp_path,
        on_change=lambda filename, findings: updates.append((filename, findings)),
        on_error=lambda filename, error: errors.append((filename, error)),
    )

    def fail_scan(*_args, **_kwargs):
        raise RuntimeError("scanner failure")

    monkeypatch.setattr(watcher_module, "scan_file", fail_scan)

    watcher._scan_and_notify(source)

    assert updates == []
    assert errors[0][0] == source
    assert isinstance(errors[0][1], RuntimeError)
