# Deploying the SecurCode platform

> Status: deployment configuration is written and the container files pass Trivy's misconfiguration checks, but **no public deployment has been made or verified** yet. Deploying requires your Render, Vercel and database accounts. Follow the steps below and run the smoke test before calling it live.

## Provider evaluation (checked November 2026; verify before you deploy)

| Need | Option | Notes |
|---|---|---|
| Frontend | **Vercel Hobby** | Static Vite build; `vercel.json` rewrites `/api/v1/*` to the API so cookies stay first-party. Rewrites to external origins count against bandwidth. |
| API | **Render web service** | Free instances sleep after inactivity (cold starts of tens of seconds). Paid "Starter" instances (about $7/month per service) stay up. |
| Worker | **Render background worker** | Background workers have **no free instance type** (cheapest is about $7/month). The low-cost alternative is `SECURCODE_EMBEDDED_WORKER=true` (below). |
| PostgreSQL | Render Postgres, or an external provider | **Free Render Postgres expires 30 days after creation** (1 GB). For anything you want to keep, use a paid Render plan (from about $6/month) or an external PostgreSQL whose free tier does not expire. Check its retention and backup terms. |
| Email | Any SMTP provider | Optional. Render blocks outbound port 25; use 587 or 465. |

Do not depend on a free tier staying free. Never store important data on an ephemeral filesystem; uploaded archives are stored in PostgreSQL for that reason.

### Recommended layouts

| Layout | Monthly cost (approx.) | Trade-off |
|---|---|---|
| **Low-cost demo**: Vercel + Render free web service with embedded worker + non-expiring external Postgres | $0 | Cold starts. Scans queued while the service sleeps start when it wakes. Worker shares CPU and memory with the API (scans still run in a separate, resource-limited subprocess). |
| **Standard**: Vercel + Render Starter API + Render Starter worker + Render Postgres Basic | ~$20 | Always-on, separate worker. Use this for anything beyond a demo. |

## 1. Prepare secrets

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"   # SECURCODE_ENCRYPTION_KEY
```

Store it in Render's environment settings, never in Git. Losing it makes stored GitHub tokens and MFA secrets unreadable: users would need to re-enrol MFA and reconnect GitHub.

## 2. Database

Create the PostgreSQL database and copy its connection string (`postgresql://user:pass@host:5432/db`). Migrations run automatically at API start (`python -m app.v1.cli migrate`). To run them manually:

```bash
cd backend
SECURCODE_ENV=production SECURCODE_DATABASE_URL=... SECURCODE_ENCRYPTION_KEY=... SECURCODE_ALLOWED_ORIGINS=https://<web> python -m app.v1.cli migrate
```

## 3. Backend on Render

Option A, blueprint: in Render choose **New → Blueprint**, select the repository, review `render.yaml` (standard layout), and fill every `sync: false` variable.

Option B, manual: **New → Web Service → Docker**, Dockerfile path `backend/Dockerfile`, Docker context `.` (repository root), health check `/api/v1/health/ready`, and these environment variables:

| Variable | Value |
|---|---|
| `SECURCODE_ENV` | `production` |
| `SECURCODE_DATABASE_URL` | your PostgreSQL URL |
| `SECURCODE_ENCRYPTION_KEY` | Fernet key from step 1 |
| `SECURCODE_PUBLIC_APP_URL` | `https://<your-vercel-domain>` |
| `SECURCODE_ALLOWED_ORIGINS` | same as above |
| `SECURCODE_COOKIE_SECURE` | `true` |
| `SECURCODE_TRUST_PROXY_HEADERS` | `true` |
| `SECURCODE_LEGACY_API` | `false` |
| `SECURCODE_EMBEDDED_WORKER` | `true` for the low-cost layout, `false` with a separate worker |
| `SECURCODE_SMTP_*` | optional |

Separate worker: **New → Background Worker → Docker**, same image settings, command `python -m app.v1.worker`, and the same database and encryption variables.

## 4. Frontend on Vercel

1. Edit `frontend/vercel.json`, replacing `REPLACE-WITH-YOUR-API-HOST` with your Render host (for example `securcode-api.onrender.com`).
2. In Vercel, import the repository with root directory `frontend` and framework Vite.
3. Set the environment variable `VITE_SAME_ORIGIN_API=true` (the build fails without it, or without an explicit `VITE_API_BASE_URL`).
4. Deploy, then set `SECURCODE_PUBLIC_APP_URL` and `SECURCODE_ALLOWED_ORIGINS` on Render to the Vercel URL and redeploy the API.

## 5. Bootstrap the first platform administrator

Administrators are created only from the CLI, never through the API:

```bash
# Render shell on the API service (or locally against the production DB URL)
python -m app.v1.cli create-admin you@example.com        # prompts for the password (not echoed, not in history)
```

Ordinary users register at `/register` and create their own organisations; platform admin is not needed for normal use.

## 6. Optional: demo organisation

```bash
SECURCODE_DEMO_PASSWORD='<long random password>' python -m app.v1.cli seed-demo
```

This creates the clearly labelled "SecurCode Demo (sample data)" organisation with the intentionally vulnerable fixture project and a security-analyst account `demo@securcode.example` (it can run scans and triage findings in the demo organisation only). It contains no real tenant data.

## 7. Email

Set `SECURCODE_SMTP_HOST`, `PORT` (587), `USERNAME`, `PASSWORD`, `FROM`. Without SMTP:

- invitations return a single-use link once to the inviting admin, who must share it securely;
- password reset and email verification links cannot be delivered in production, so configure SMTP before you rely on them.

## 8. GitHub integration

See [`../GITHUB-INTEGRATION.md`](../GITHUB-INTEGRATION.md#multi-tenant-platform-integration).

## 9. Smoke test (required before calling the deployment live)

```bash
WEB=https://<your-vercel-domain>
curl -fsS $WEB/api/v1/health/live      # {"status":"ok"}
curl -fsS $WEB/api/v1/health/ready     # {"status":"ready","database":"ok"}  (503 = DB down or migrations pending)
curl -fsS $WEB/api/v1/health/worker    # 200 when a worker heartbeat is < 90 s old, 503 otherwise
```

Then, in a browser: register, create an organisation, create an upload project, upload `scanner-fixtures/projects/demo-vulnerable-app` as a `.zip`, wait for the scan to complete (9 findings), open a finding, and export CSV. The GitHub Actions workflow `deploy.yml` automates the health part after deploy hooks run.

## 10. Rollback

- **Application:** in Render, use **Deploys → Rollback** to the previous image. In Vercel, use **Deployments → Promote** on the previous build.
- **Database:** migrations are additive. To revert the platform schema use `python -m alembic downgrade <revision>`; this **drops** `sc_` tables, so take a backup first.

## 11. Backup and restore

**PostgreSQL:**

```bash
pg_dump --format=custom --no-owner "$SECURCODE_DATABASE_URL" -f securcode-$(date +%F).dump
pg_restore --clean --if-exists --no-owner --dbname "$TARGET_DATABASE_URL" securcode-YYYY-MM-DD.dump
```

Use your provider's automated backups or point-in-time recovery where available, and test a restore into a scratch database regularly. Dumps contain customer code snippets and vulnerability data: store them encrypted and never commit them.

**SQLite (local and legacy):** `python -m app.v1.cli migrate` takes an online, integrity-checked backup to `backups/` before every migration. `scripts/sqlite_backup_restore.py` handles manual backup and restore.

After restoring, run `python -m app.v1.cli verify-audit` to confirm the audit chain is intact.
