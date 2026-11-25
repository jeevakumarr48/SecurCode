"""Test-session isolation.

Several modules open the database at import time. Without this file a plain
``pytest`` run would write to the real ``backend/sentinelops.db``. Every test
session therefore gets throwaway database locations *before* any application
module is imported. Set SECURCODE_TEST_DATABASE_URL to run the /api/v1 suite
against PostgreSQL instead of SQLite.
"""

import os
import sys
import tempfile
from pathlib import Path

_TEST_ROOT = Path(tempfile.mkdtemp(prefix="securcode-tests-"))
os.environ["SECURCODE_ENV"] = "test"
os.environ["SECURCODE_DATABASE_PATH"] = str(_TEST_ROOT / "legacy-test.db")
os.environ.setdefault("SECURCODE_DISABLE_WATCHER", "true")
if os.getenv("SECURCODE_TEST_DATABASE_URL"):
    os.environ["SECURCODE_DATABASE_URL"] = os.environ["SECURCODE_TEST_DATABASE_URL"]
    os.environ.setdefault("SECURCODE_LEGACY_API", "true")
else:
    os.environ["SECURCODE_DATABASE_URL"] = f"sqlite:///{(_TEST_ROOT / 'platform-test.db').as_posix()}"
os.environ.setdefault("SECURCODE_ENCRYPTION_KEY", "8hjdug66S518lUi-61oJegjIei5xYyx0uc-nNMiMN5s=")

BACKEND_DIR = Path(__file__).resolve().parent
for candidate in (BACKEND_DIR, BACKEND_DIR.parent):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))
