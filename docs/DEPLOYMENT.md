# Deployment and recovery

## Deploy the backend for a Vercel-hosted frontend

The backend needs a persistent Linux web service with a durable mounted disk and the repository's backend source tree available at runtime. It is not a stateless/serverless API: scans read local files under the checked-out SecurCode workspace, SQLite stores operational data on disk, and login throttling plus scan concurrency are process-local. Do not deploy this API as a Vercel Function or scale it across instances.

### 1. Provision the backend service and disk

Choose a provider that supports a continuously running Python web service and persistent mounted storage. Create the disk before the first deployment, mount it at a fixed path (for example `/var/data`), and ensure the service user can read and write there. Do not point the database at the checkout, a temporary directory, or an ephemeral container filesystem.

Make the complete SecurCode repository checkout available to the backend. The scanner resolves project paths relative to the repository workspace and the bundled demo source is inside that checkout. If the provider allows selecting a root directory, `backend` can be the service working directory; the repository root still needs to be present above it for workspace scanning.

### 2. Configure production environment variables

Set these in the provider's service settings/secret manager (not in source control):

| Variable | Value |
|---|---|
| `SECURCODE_ENV` | `production` |
| `SECURCODE_DEMO_MODE` | `false` |
| `SECURCODE_ALLOWED_ORIGINS` | Exact Vercel frontend origin, such as `https://your-app.vercel.app` (scheme and hostname only; no path, trailing route, wildcard, or preview wildcard) |
| `SECURCODE_DATABASE_PATH` | Absolute file path on the mounted disk, for example `/var/data/sentinelops.db` |
| `PORT` | The port supplied by the hosting provider; the start command below uses it, with `8000` as a local fallback |

`SECURCODE_DATABASE_PATH`'s parent directory must already exist when the application starts; mount the disk at `/var/data` before starting the process. The application creates/initializes the SQLite file at that configured path. This creates a separate host-side database; it neither moves nor overwrites the local `backend/sentinelops.db`.

For the first administrator only, set `SECURCODE_BOOTSTRAP_TOKEN` to a cryptographically random value of at least 32 characters using the provider's secret manager. After creating the administrator, remove that environment variable and restart the service. Existing accounts do not require the bootstrap token at startup. Never put the token, password, or bearer token in a command, source file, build variable, or logs.

`SECURCODE_ALLOWED_ORIGINS` is parsed as a comma-separated list of exact origins and production requires HTTPS. For Vercel preview deployments, use a stable custom domain or explicitly list the exact preview origins that are intended to have access. Do not configure `*` or a wildcard preview hostname. Set Vercel's `VITE_API_BASE_URL` to the backend's public HTTPS base URL at frontend build time.

### Production request and session security

The API uses opaque bearer sessions; it does not set authentication cookies. The frontend keeps the bearer token in memory and sends it in the `Authorization` header. CORS credentials are disabled. `SameSite`, `Secure`, and `HttpOnly` cookie attributes therefore do not apply. Do not add cookie-based auth without designing and testing CSRF protection. API responses use `Cache-Control: no-store` and `Pragma: no-cache`; sessions expire after eight hours and are revoked on logout, password change (other sessions), or account disablement.

The production FastAPI app disables debug mode and Swagger, ReDoc, and OpenAPI. Those documentation routes are also excluded from the production unauthenticated-path list. The API adds `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, and a restrictive API Content Security Policy.

TLS termination, HTTP-to-HTTPS redirects, and HSTS must be configured at the hosting edge; the app does not set HSTS because it may run behind a TLS-terminating proxy. Configure the separately hosted frontend's security headers at its hosting edge as well, testing the Content Security Policy against the built application assets and styles. Do not assume the API's headers protect the frontend.

When running behind a reverse proxy, trust forwarded client/protocol headers only from the hosting provider's documented proxy IPs or CIDRs. Configure Uvicorn's forwarded-header allowlist accordingly; never trust forwarded headers from `*` or from arbitrary clients. If the provider cannot supply a stable trusted-proxy range, do not use forwarded headers to derive client IPs or security decisions. Login throttling allows at most 10 attempts per client address in a rolling five-minute process-local window; a successful login clears that address's failures. The counter resets on process restart and is not shared across workers or replicas. The app's login throttle and scan semaphore are process-local; keep one worker and one replica.

### 3. Install and start the backend

Use the deployment dependencies in `backend/requirements-deploy.txt`. From the `backend` working directory, configure this production start command:

```sh
python -m uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-8000}" --workers 1
```

The provider must pass its assigned `PORT` to the process. The single worker is intentional: login throttling and the built-in scan semaphore are in-memory and are not shared across workers or replicas. Do not increase workers, enable overlapping instances, or autoscale this service.

Configure the provider's readiness/health-check path as `/healthz`. Production startup also checks the database path and mount directory. When the configured database has no accounts, startup requires the bootstrap token; after an account exists, it can be removed. Production Swagger, ReDoc, and OpenAPI endpoints are disabled.

### 4. Configure the Vercel frontend

In the Vercel project settings, set `VITE_API_BASE_URL` to the backend's exact public HTTPS API base URL, with no path suffix. Trigger a new frontend build after changing it because Vite embeds this value at build time. Set the same frontend's exact HTTPS origin in the backend's `SECURCODE_ALLOWED_ORIGINS`. The Vite localhost proxy is development-only; production builds require a configured HTTPS API base URL.

### 5. Configure HTTPS and verify

Use the provider's TLS termination, redirect HTTP to HTTPS, and add HSTS at the hosting edge. The API emits `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, and a restrictive Content Security Policy, but it does not set HSTS. Configure appropriate response security headers for the Vercel frontend as well.

Before allowing use, verify:

1. `https://<backend-host>/healthz` returns healthy.
2. HTTP requests redirect to HTTPS and HTTPS responses include HSTS.
3. The Vercel frontend origin is exactly allowed by API CORS; an unrelated origin is not allowed.
4. The running service's `SECURCODE_DATABASE_PATH` points inside the mounted disk, and the health check reports the database available.
5. After administrator bootstrap, remove `SECURCODE_BOOTSTRAP_TOKEN`, restart, and verify login still works.
6. Register a project whose source path is present in the backend workspace, scan it, and verify the resulting scan persists after restarting the service.
7. Create a separate backup and complete an isolated restore rehearsal using the procedures below.

The application cannot prove that a provider mount is durable or correctly protected. Provider disk provisioning, access controls, restart persistence, backup retention, and recovery must be verified by the operator. No production service or Vercel deployment is configured or verified by this guide.

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

The schema initializer applies idempotent additive migrations on API startup and records versions in `schema_migrations`. Startup opens only the configured `SECURCODE_DATABASE_PATH`; it does not search for, copy, replace, or overwrite another database. A missing configured file is initialized as a new database, so verify the mounted path before starting the service. No scheduled backup, retention, encryption, or automatic database switch is implemented by SecurCode.

Connections enable foreign-key enforcement and a 10-second busy timeout. The application does not change `journal_mode`; fresh databases use SQLite's default rollback journal (`DELETE`). If WAL is enabled operationally, the mounted filesystem must support SQLite's WAL shared-memory and locking requirements. Keep the database on a provider-supported persistent filesystem and the API to one process and one replica. The online backup API is used for consistent backups, including when journal state needs coordination.

Create a backup with the repository utility. The source must be the exact path used by the API; the destination directory must already exist, and the backup destination must be new. The utility opens the source read-only, uses SQLite's online backup API, and checks both `integrity_check` and `foreign_key_check` before reporting success. Store the result on a separate, access-controlled destination:

```powershell
$env:SECURCODE_DATABASE_PATH = "D:\securcode-data\sentinelops.db"
$env:SECURCODE_BACKUP_PATH = "E:\securcode-backups\sentinelops-2026-11-06.sqlite"
& .\backend\.venv\Scripts\python.exe .\scripts\sqlite_backup_restore.py backup $env:SECURCODE_DATABASE_PATH $env:SECURCODE_BACKUP_PATH
```

Protect and encrypt backup files according to the data classification of scanned project metadata. Retain them separately from the service volume. Do not treat a successful backup command as a recovery test.

To rehearse recovery, restore to a new path in an isolated location; never restore over the live database during a rehearsal. The restore utility verifies the source backup before copying, verifies the restored database afterward, and refuses an existing destination. It never switches or replaces the configured database:

```powershell
$env:SECURCODE_BACKUP_PATH = "E:\securcode-backups\sentinelops-2026-11-06.sqlite"
$env:SECURCODE_RESTORE_PATH = "D:\securcode-recovery-test\sentinelops-restored.sqlite"
& .\backend\.venv\Scripts\python.exe .\scripts\sqlite_backup_restore.py restore $env:SECURCODE_BACKUP_PATH $env:SECURCODE_RESTORE_PATH
```

For a real recovery, stop the API first. Restore to a new file on the durable volume and confirm the successful integrity/foreign-key checks and the expected SecurCode data before changing the service's `SECURCODE_DATABASE_PATH` to that restored file and restarting. Do not overwrite or delete the previous database as part of the switch; retain it until service health and the restored accounts, findings, scan history, and assignments have been checked. The application startup performs additive schema migrations, so restore with a compatible application version and retain a separate pre-upgrade backup.

The isolated repository tests verify restart persistence and that a restore retains an administrator, findings, scan history, assignment state/history, and schema versions. They use only temporary databases. A successful local test does not establish that a provider volume is durable, correctly mounted, or recoverable; complete a restore rehearsal on the selected hosting service.

## Release checks

- Verify `https://<api-host>/healthz` returns healthy after deployment.
- Confirm HTTP redirects to HTTPS and inspect the HTTPS response for HSTS.
- Confirm the browser frontend's exact HTTPS origin matches `SECURCODE_ALLOWED_ORIGINS`.
- Confirm API and frontend security headers at their respective hosts.
- Confirm the API uses the intended mounted SQLite path and that the mount survives a service restart.
- Rehearse restore from a separately stored backup.
- Keep authenticated production at one API process/replica until rate limiting is shared and storage is suitable for the deployment topology.
- GitHub URLs in SecurCode are metadata only. GitHub repository retrieval and remote scanning are not implemented. CodeQL workflow execution and live SARIF artifact retrieval require external GitHub access and are not validated by local tests.
