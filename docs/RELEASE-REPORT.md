# SecurCode final release report

**Audit date:** 2026-11-06
**Decision:** **NOT READY TO DEPLOY**
**Production URL:** None. No production deployment was performed.

## Release status

| Area | Status | Evidence and limitations |
|---|---|---|
| Backend authentication and sessions | PASS | Full backend tests cover password hashing, bootstrap, session expiration, logout/revocation, account disabling, throttling, and role enforcement. |
| Project/workspace isolation | PASS | Two-user/two-project API tests cover cross-project read/write/scan/SARIF denial and administrator membership grant. Global operational views remain administrator-only. |
| Application security review | PASS | Reviewed authentication/middleware, project checks, SQLite parameterization, scanner filesystem/process boundaries, API headers/CORS, audit redaction, and reports. Regressions cover selected controls. This was not an independent penetration test; see residual risks. |
| Dependency audit | PASS | Frontend `npm audit`: zero reported vulnerabilities. Python `pip_audit -r requirements-dev.txt`: no known vulnerabilities found. Dependency results do not prove application security. |
| Database and local recovery | PASS | Migrations through v7, idempotent initialization, live-database integrity, and temporary SQLite backup/restore test passed. |
| Production storage/recovery | BLOCKED | No production volume is configured. Durability, permissions, backup retention, and a restore rehearsal on the actual hosting service are not verified. |
| Scanner benchmark | PASS | 12 hand-curated fixtures: TP=15, FP=0, FN=0; precision=1.000, recall=1.000, F1=1.000. This is not a representative real-world corpus or accuracy estimate. |
| Frontend | PASS | Two unit tests and one isolated Playwright journey cover login, project/source registration, scan, findings, invalid/successful assignment with duplicate-submit guard, CSV report download, and logout. Incident/audit journeys and exhaustive navigation/control/filter/responsive coverage are NOT VERIFIED. |
| GitHub product integration | NOT IMPLEMENTED | Project repository URLs are metadata. SecurCode does not fetch remote GitHub repositories or Actions artifacts. Local SARIF import and workflow configuration exist, but no live Actions/SARIF round-trip was verified. |
| Production configuration | BLOCKED | No configured hosting service/domain/credentials were found. TLS redirect, HSTS, frontend headers, production CORS, durable storage, restart persistence, and critical post-deploy journeys therefore cannot be verified. |
| Local API health | PASS | The active local development API returned healthy status and SQLite readiness. This is not a production health check. |

## Exact validation results

- `.\validate.ps1`: backend **177 passed, 2 skipped** in 16.43s; frontend **2 passed, 0 failed**; production build passed with Vite 8.3.4 (JS 299.15 kB / 86.75 kB gzip; CSS 35.98 kB / 7.85 kB gzip). The local validation build used the script's placeholder HTTPS API base URL, not a production endpoint.
- `Set-Location frontend; npm run test:e2e`: **1 passed** in 7.8s. The run used its isolated test setup; it did not alter the configured application database.
- `Set-Location backend; .\.venv\Scripts\python.exe -m pytest -q test_config.py`: **12 passed**, including a production-mode subprocess check for disabled Swagger, ReDoc, and OpenAPI, plus configuration tests for token removal only after an account exists.
- `Set-Location backend; .\.venv\Scripts\python.exe -m pytest -q security_engine\test_multilanguage.py security_engine\test_benchmark.py`: **17 passed**, including the `child_process.exec` alias detection regression and a safe unrelated-alias case.
- `Set-Location backend; .\.venv\Scripts\python.exe -m security_engine.benchmark`: **12 fixtures; TP=15, FP=0, FN=0; precision=1.000, recall=1.000, F1=1.000**. Python: 9 TP / 0 FP / 0 FN; JavaScript: 6 TP / 0 FP / 0 FN. Full results are in [scanner-benchmark.json](../backend/reports/scanner-benchmark.json).
- `Set-Location frontend; npm audit`: **0 vulnerabilities**.
- `Set-Location backend; .\.venv\Scripts\python.exe -m pip_audit -r requirements-dev.txt`: **No known vulnerabilities found**.
- `git diff --check`: passed; Git emitted only line-ending conversion warnings.
- Read-only local database check: configured file exists, SQLite `integrity_check` returned `ok`, with one administrator account. No account or database data was modified.
- Local API `/status` and `/healthz`: healthy. These endpoints ran in development configuration, not behind a production host.

The two skipped backend cases are optional live Trivy tests; they are not reported as passing. No test failures were reported.

## Security review findings and limitations

- Corrected `JSSEC003` to detect simple local variable aliases of `child_process.exec`/`execSync`. The matcher remains lexical; imported/destructured aliases and general JavaScript/TypeScript dataflow are unsupported.
- Corrected production bootstrap configuration: the secret is required for an empty private-production database, but may be removed after accounts exist. Production Swagger, ReDoc, and OpenAPI routes are disabled.
- API security headers and exact HTTPS CORS origin validation are application-configured. HSTS/HTTPS redirect and frontend response headers must be configured at the hosting edge and were not testable here.
- Login throttling and scan concurrency are process-local. Use one API process and one replica; multi-instance readiness is NOT VERIFIED.
- SQLite is the only supported database. The application cannot prove that a path is a durable mount. Scheduled backups, backup encryption/retention, and hosted recovery are operator responsibilities.
- The scanner is static and does not execute scanned source. Per-file parser processing cannot be interrupted. Benchmark metrics are small-fixture regression results only.
- No independent penetration test, live external scanner run, or production workload assessment was performed.

## GitHub status

SecurCode does not clone or scan repository URLs submitted through the application and does not retrieve GitHub Actions artifacts. The SARIF import API is local and tested with deterministic fixtures. GitHub Actions workflow execution, private repository authorization, and live SARIF artifact round-trip are NOT VERIFIED / NOT IMPLEMENTED.

## Deployment blockers and required manual actions

1. Select and provision a hosting provider/service, production domain, and deployment permissions. None are configured in this environment.
2. Provide an exact HTTPS frontend origin and configure the API's matching `SECURCODE_ALLOWED_ORIGINS`.
3. Configure TLS termination, HTTP-to-HTTPS redirection, HSTS, and frontend security headers; verify them against the real public host.
4. Provision a durable, access-restricted SQLite volume and set its absolute `SECURCODE_DATABASE_PATH`. Keep the API to one process/replica.
5. Configure `SECURCODE_ENV=production` and `SECURCODE_DEMO_MODE=false`. Use a secret manager for the one-time bootstrap token if the production database has no accounts, then remove the token after first-admin setup.
6. Configure a separate encrypted backup destination and complete an isolated restore rehearsal on the selected host.
7. Deploy only after those controls are in place, then verify HTTPS, health, administrator login, project creation, scan, finding assignment/persistence, incidents/audit/reports, unauthorized-request denial, and data persistence after restart.

These are real provider/domain/permission requirements; no deployment URL or production success is claimed.

## Rollback procedure

No deployment occurred, so no production rollback was performed. For a future deployment:

1. Stop or disable writes before changing application versions.
2. Preserve a new copy/snapshot of the current production SQLite database without overwriting an existing backup.
3. Roll back the application to a previously verified release only after checking that it is compatible with the current additive schema. Migrations 1–7 are tested as additive locally, but hosted old-version compatibility is NOT VERIFIED.
4. Do not restore an older database automatically; that can lose post-backup user data. Restore only with explicit operator approval, using a separately verified backup and a new target after preserving the current database.
5. Start the selected version and verify database integrity, `/healthz`, administrator login, and critical read/write workflows before reopening access.
