from pathlib import Path
from threading import Event

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
