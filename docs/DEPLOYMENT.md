# Deployment and recovery

## Private authenticated production

SQLite is the only supported application database. Before starting a private production service:

1. Mount durable storage and create the mount directory before starting the API.
2. Set `SECURCODE_ENV=production`, `SECURCODE_DEMO_MODE=false`, an exact HTTPS frontend origin in `SECURCODE_ALLOWED_ORIGINS`, an absolute `SECURCODE_DATABASE_PATH` inside the mounted directory, and a one-time `SECURCODE_BOOTSTRAP_TOKEN` with at least 32 characters before the first account is created. Startup refuses to serve an empty private-production database without this token; after at least one account exists, the token may be removed and the service can restart without it.
3. Keep the API on one process and one replica (`--workers 1`). Login throttling and the built-in scan semaphore are process-local. Do not autoscale or run overlapping API workers until a shared rate limiter and a production-supported shared database are implemented. The SQLite-backed demo cooldown is shared only by processes that use the same database file.
4. Terminate TLS at the hosting layer, redirect HTTP to HTTPS there, and configure HSTS on the HTTPS response. A conservative starting value is `Strict-Transport-Security: max-age=31536000`; add `includeSubDomains` only when every subdomain is HTTPS-capable. Do not enable preload without a separate domain-wide review.
5. Configure the API CORS allowlist with the exact frontend origin, including scheme and host, and no path or wildcard. The API rejects non-HTTPS production origins. `allow_credentials` is disabled.
6. Configure appropriate security headers for the separately hosted frontend. The API emits `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, and a restrictive Content Security Policy. FastAPI Swagger, ReDoc, and OpenAPI routes are disabled in production. The API deliberately does not set HSTS because TLS is terminated by the host.
7. Initialize the first administrator through the deployment secret manager. Remove the bootstrap token from the service environment immediately after use; retain it only in a separate protected recovery procedure if account bootstrap must be made available again, and never enable bootstrap on a database that already contains accounts. Never put passwords, bearer tokens, or the bootstrap token in command-line arguments, source files, or logs.

The startup checks reject missing/relative private-production database paths and a missing mount directory. They cannot prove that a directory is durable, encrypted, correctly permissioned, or backed up; verify those properties with the hosting provider. A wrong but existing mount path can still create an empty database, so compare the configured path with the mounted volume before first startup.

The public Render demo is intentionally separate from this private-production profile. A free/ephemeral host has no durable SQLite guarantee and is suitable only for disposable demo data. Do not use the example demo configuration for authenticated production.

## SQLite backup and restore

The schema initializer applies idempotent additive migrations on API startup and records versions in `schema_migrations`. Preserve a backup before application upgrades or storage changes. No scheduled backup, retention, encryption, or automated restore is implemented by SecurCode.

Create an online consistent backup with Python's SQLite backup API. The target must not already exist. Set the source to the exact database path used by the API and store the backup on a separate, access-controlled destination:

```powershell
$env:SECURCODE_DATABASE_PATH = "D:\securcode-data\sentinelops.db"
$env:SECURCODE_BACKUP_PATH = "E:\securcode-backups\sentinelops-2026-11-06.sqlite"
@'
import os
import sqlite3
from pathlib import Path

source_path = Path(os.environ["SECURCODE_DATABASE_PATH"])
backup_path = Path(os.environ["SECURCODE_BACKUP_PATH"])
if not source_path.is_file():
    raise SystemExit("Configured source database does not exist.")
if backup_path.exists() or not backup_path.parent.is_dir():
    raise SystemExit("Backup target exists or its destination directory is missing.")
source = sqlite3.connect(source_path.resolve().as_uri() + "?mode=ro", uri=True)
try:
    with sqlite3.connect(backup_path) as backup:
        source.backup(backup)
        if backup.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise SystemExit("Backup integrity check failed.")
finally:
    source.close()
print("Backup completed and passed SQLite integrity_check.")
'@ | & .\backend\.venv\Scripts\python.exe -
```

Protect and encrypt backup files according to the data classification of scanned project metadata. Retain them separately from the service volume. Do not treat a successful backup command as a recovery test.

To rehearse recovery, use a new empty path in an isolated location; never restore over the live database during a rehearsal. Stop the target API before a real restore, preserve its current database separately without overwriting an existing copy, and restore only a verified backup:

```powershell
$env:SECURCODE_BACKUP_PATH = "E:\securcode-backups\sentinelops-2026-11-06.sqlite"
$env:SECURCODE_RESTORE_PATH = "D:\securcode-recovery-test\sentinelops-restored.sqlite"
@'
import os
import sqlite3
from pathlib import Path

backup_path = Path(os.environ["SECURCODE_BACKUP_PATH"])
restore_path = Path(os.environ["SECURCODE_RESTORE_PATH"])
if not backup_path.is_file():
    raise SystemExit("Backup file does not exist.")
if restore_path.exists() or not restore_path.parent.is_dir():
    raise SystemExit("Restore target exists or its destination directory is missing.")
source = sqlite3.connect(backup_path.resolve().as_uri() + "?mode=ro", uri=True)
try:
    if source.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
        raise SystemExit("Backup integrity check failed.")
    with sqlite3.connect(restore_path) as restored:
        source.backup(restored)
        if restored.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise SystemExit("Restored database integrity check failed.")
        versions = [row[0] for row in restored.execute(
            "SELECT version FROM schema_migrations ORDER BY version"
        )]
        print(f"Restore verified; applied schema versions: {versions}")
finally:
    source.close()
'@ | & .\backend\.venv\Scripts\python.exe -
```

The repository test suite also backs up and restores a temporary database, checks `PRAGMA integrity_check`, verifies retained scan data, and checks migration versions 1 through 7. A successful local test does not replace a recovery rehearsal on the actual hosting volume.

## Release checks

- Verify `https://<api-host>/healthz` returns healthy after deployment.
- Confirm HTTP redirects to HTTPS and inspect the HTTPS response for HSTS.
- Confirm the browser frontend's exact HTTPS origin matches `SECURCODE_ALLOWED_ORIGINS`.
- Confirm API and frontend security headers at their respective hosts.
- Confirm the API uses the intended mounted SQLite path and that the mount survives a service restart.
- Rehearse restore from a separately stored backup.
- Keep authenticated production at one API process/replica until rate limiting is shared and storage is suitable for the deployment topology.
- GitHub URLs in SecurCode are metadata only. GitHub repository retrieval and remote scanning are not implemented. CodeQL workflow execution and live SARIF artifact retrieval require external GitHub access and are not validated by local tests.
