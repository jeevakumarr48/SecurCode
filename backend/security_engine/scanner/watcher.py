
import os
import time
from pathlib import Path
from threading import Event, Thread
from typing import Callable

from .engine import (
    SKIPPED_DIRECTORIES,
    SUPPORTED_EXTENSIONS,
    _should_skip_file,
    scan_file,
)


class SourceFileWatcher:
    """Lightweight polling watcher for supported source files."""

    def __init__(
        self,
        root: str | Path,
        on_change: Callable[[Path, list], None],
        interval: float = 1.0,
        debounce: float = 0.5,
    ):
        self.root = Path(root).resolve()
        self.on_change = on_change
        self.interval = max(0.2, interval)
        self.debounce = max(0.1, debounce)
        self._stop_event = Event()
        self._thread = None
        self._known_files = {}

    def _snapshot(self):
        snapshot = {}

        if not self.root.is_dir():
            return snapshot

        for directory, directories, filenames in os.walk(
            self.root, followlinks=False
        ):
            current = Path(directory)
            directories[:] = [
                name
                for name in directories
                if name not in SKIPPED_DIRECTORIES
                and not (current / name).is_symlink()
            ]

            for name in filenames:
                path = current / name

                if (
                    path.is_symlink()
                    or path.suffix.lower() not in SUPPORTED_EXTENSIONS
                    or _should_skip_file(path)
                ):
                    continue

                try:
                    stat = path.stat()
                    snapshot[str(path)] = (stat.st_mtime_ns, stat.st_size)
                except OSError:
                    continue

        return snapshot

    def _scan_and_notify(self, path):
        try:
            self.on_change(path, scan_file(path))
        except (OSError, UnicodeError) as error:
            print(f"SecurCode could not scan {path}: {error}")

    
    def _run(self):
        pending = {}
        if not self._known_files:
            self._known_files = self._snapshot()


        while not self._stop_event.wait(self.interval):
            current = self._snapshot()
            now = time.monotonic()

            for filename, signature in current.items():
                if self._known_files.get(filename) != signature:
                    pending[filename] = (signature, now)

            for filename, (signature, changed_at) in list(pending.items()):
                if filename not in current:
                    pending.pop(filename, None)
                elif current[filename] != signature:
                    pending[filename] = (current[filename], now)
                elif now - changed_at >= self.debounce:
                    self._scan_and_notify(Path(filename))
                    pending.pop(filename, None)

            self._known_files = current


    def start(self):
        """Start monitoring in a background thread."""
        if self._thread and self._thread.is_alive():
            return

        self._stop_event.clear()
        self._known_files = self._snapshot()
        self._thread = Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        """Stop monitoring."""
        self._stop_event.set()

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)

        self._thread = None
