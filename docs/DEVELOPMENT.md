# Local development, demo and troubleshooting

Requirements: **Python 3.11+** (3.12–3.14 tested; SQLAlchemy 2.1 needs ≥ 3.11), **Node.js 22**, Git. PostgreSQL and Docker are optional.

## 1. First-time setup (Windows PowerShell)

```powershell
cd C:\Users\jeeva\Downloads\SecurCode\backend
.\.venv\Scripts\Activate.ps1                     # existing virtual environment
python -m pip install -r requirements-dev.txt   # adds SQLAlchemy, Alembic, argon2, cryptography, ...

# Back up the database, then add the platform tables (additive; legacy tables untouched)
python -m app.v1.cli migrate

# Optional: copy your legacy admin, projects and scan history into a "Legacy workspace" org
python -m app.v1.cli import-legacy
```

`migrate` writes an integrity-checked backup to `..\backups\` before touching the database. Your existing administrator signs in to the new console with the **same username and password** as before, typed into the email field. The password hash is upgraded to Argon2id on first login.

macOS/Linux: `source .venv/bin/activate` (or create one with `python3 -m venv .venv`); the commands are otherwise the same.

## 2. Run the stack (three terminals)

```powershell
# Terminal 1: API (legacy console API + /api/v1)
cd backend; .\.venv\Scripts\Activate.ps1
python -m uvicorn app.main:app --reload --port 8000

# Terminal 2: scan worker (scans stay "queued" without it)
cd backend; .\.venv\Scripts\Activate.ps1
python -m app.v1.worker

# Terminal 3: web console
cd frontend
npm ci
npm run dev        # http://localhost:5173  (legacy console: http://localhost:5173/legacy.html)
```

In development an encryption key is generated automatically in `backend/.securcode-dev.key` (gitignored), and emails are printed to the API terminal.

To use PostgreSQL locally instead of SQLite, set `SECURCODE_DATABASE_URL=postgresql://user:pass@localhost:5432/securcode` before `migrate` and before starting the API and worker. The legacy console API is disabled on PostgreSQL unless `SECURCODE_LEGACY_API=true`.

### Docker alternative

```bash
cp .env.example .env    # set POSTGRES_PASSWORD and SECURCODE_ENCRYPTION_KEY
docker compose up --build
# http://localhost:8080
```

## 3. Demo walkthrough (about 5 minutes)

1. Open http://localhost:5173, choose **Create account**, then create an organisation.
2. **New project → Upload source archive**. Zip `scanner-fixtures/projects/demo-vulnerable-app` and upload it, then **Start scan**. Progress updates live; the scan finds 9 issues.
3. **Team & invitations**: invite a developer. Without SMTP, copy the one-time link shown and open it in a private window to register as that user.
4. Open **Vulnerabilities → Tainted SQL execution**: assign it to the developer and mark it *Triaged*.
5. As the developer, go to **My remediation**, set the finding to *In progress*, comment, then set it to *Fixed*.
6. As the owner, upload `scanner-fixtures/projects/demo-vulnerable-app-fixed` and scan. Seven findings become **Verified fixed** and two remain.
7. Open the scan, choose **Compare with another scan**, then **Reports → Printable report**, and export **SARIF/CSV** from Vulnerabilities.
8. Sign in as a third user in another organisation and open the first organisation's URL. You get "Organization not found".

Or create a seeded demo organisation: `$env:SECURCODE_DEMO_PASSWORD='<long password>'; python -m app.v1.cli seed-demo` (then run the worker).

## 4. Tests

```powershell
cd backend
python -m pytest -q                                  # legacy + platform suites, isolated temp databases
python -m pytest tests_v1 -q                         # platform only
$env:SECURCODE_TEST_DATABASE_URL='postgresql://...'; python -m pytest tests_v1 -q   # on PostgreSQL
python -m security_engine.benchmark_v2               # extended-rule benchmark
ruff check app/v1 tests_v1

cd ..\frontend
npm test                 # node tests + Vitest
npm run typecheck; npm run lint
npm run test:e2e:platform   # Playwright: starts API, worker and Vite on a throwaway DB (needs Chrome or `npx playwright install chromium`)
```

`backend/conftest.py` forces every pytest run onto temporary databases. Before this change, running the legacy tests without `SECURCODE_DATABASE_PATH` wrote to `backend/sentinelops.db`.

## 5. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Scan stays **queued** | The worker is not running. Start `python -m app.v1.worker`. `GET /api/v1/health/worker` returns 503 when no worker has reported in the last 90 s. |
| `ERROR: No matching distribution found for SQLAlchemy==2.1.9` | Python older than 3.11. Use Python 3.11+. |
| `/api/v1/health/ready` → `migrations_pending` | Run `python -m app.v1.cli migrate`. |
| Production start fails with "requires SECURCODE_DATABASE_URL pointing at PostgreSQL" | Expected: production refuses SQLite unless `SECURCODE_ALLOW_SQLITE_IN_PRODUCTION=true` (single host with a durable disk only). |
| `CSRF token missing or invalid` | The page was open across a sign-in on another tab. Reload; the session payload carries the current token. |
| `429 Too many requests` at login | Rate limit (30 per IP or 10 per account per 5 minutes). Wait 5 minutes. |
| Account locked | 8 failed logins lock for 15 minutes. A platform admin can re-enable from **Platform administration**. |
| `Stored credential could not be decrypted` | `SECURCODE_ENCRYPTION_KEY` changed. Restore the old key, or reconnect GitHub and re-enrol MFA. |
| Vite build fails with `Set VITE_API_BASE_URL ... or VITE_SAME_ORIGIN_API=true` | Intentional production guard; choose how the browser reaches the API. |
| `disk I/O error` running tests on a network or virtual drive | SQLite cannot lock files there. Point `SECURCODE_DATABASE_PATH` at a local disk (conftest already uses the system temp directory). |
