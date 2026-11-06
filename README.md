# SecurCode

SecurCode is a lightweight, local-first static application security testing (SAST) tool. It scans source files without executing them, persists scan history in SQLite, and presents the results in a React/Vite security operations console.

**Release status:** not deployed to production. No production host, domain, credentials, or durable volume is configured in this workspace. GitHub repository URLs are metadata only; SecurCode does not fetch remote repositories or retrieve GitHub Actions artifacts. See [deployment and recovery](docs/DEPLOYMENT.md) and the [final release report](docs/RELEASE-REPORT.md).

## Architecture

- `backend/app/` contains the FastAPI application and REST routes.
- `backend/security_engine/scanner/engine.py` owns file discovery, language routing, skipped-directory policy, and duplicate suppression.
- `backend/security_engine/scanner/python.py` contains Python AST rules.
- `backend/security_engine/scanner/javascript.py` contains conservative JavaScript and TypeScript source-pattern rules.
- `backend/database.py` stores scan results, project records, finding lifecycle state, audit events, and incidents in SQLite.
- `frontend/` contains the React/Vite dashboard.
- `backend/config.py` validates environment settings, database location, CORS origins, and scan limits.

See [Architecture](docs/ARCHITECTURE.md), [Security assumptions](docs/SECURITY.md), and [.env.example](.env.example) for implementation boundaries and supported configuration. The sample file documents safe defaults; set values in the process environment or hosting provider before starting the service.

The scanner never executes target source code. The API resolves every requested path inside the repository workspace, rejects absolute paths and traversal segments, and does not follow symlinked directories during discovery. Supported source symlinks are reported as scan errors instead of being silently treated as scanned. Discovery is bounded by `SECURCODE_MAX_SCAN_FILES` (default 5,000), `SECURCODE_MAX_SCAN_DEPTH` (default 30), `SECURCODE_MAX_SCAN_SECONDS` (default 120), `SECURCODE_MAX_SOURCE_FILE_BYTES` (default 2,000,000), and `SECURCODE_MAX_SCAN_BYTES` (default 100,000,000). A scan that reaches a limit, encounters inaccessible directories, unreadable or undecodable source files, or Python syntax errors is marked partial or failed rather than reported clean. Time and size limits are checked between files; they cannot interrupt a parser already processing one file.

## Supported Coverage

### Python

Python files are analyzed with the standard-library AST parser. Implemented rules are:

- `SEC001` (HIGH): `eval()` dynamic evaluation.
- `SEC002` (HIGH): `subprocess.call()` and subprocess shell execution. The legacy `subprocess.call()` rule remains supported.
- `PYSEC002` (HIGH): `os.system()` and `os.popen()` command execution.
- `PYSEC003` (HIGH): unsafe `pickle`, `dill`, `marshal`, and unsafe YAML deserialization.
- `PYSEC004` (MEDIUM): dynamically assembled SQL passed to `execute()` or `executemany()`.
- `PYSEC006` (MEDIUM): hardcoded credential-like assignments.

### JavaScript and TypeScript

JavaScript (`.js`, `.jsx`, `.mjs`, `.cjs`) and TypeScript (`.ts`, `.tsx`) use a dependency-free conservative line-pattern scanner. It detects:

- `JSSEC001` (HIGH): `eval()`.
- `JSSEC002` (HIGH): `Function()` and `new Function()`.
- `JSSEC003` (HIGH): `exec()` and `execSync()` command execution.
- `JSSEC004` (HIGH): `spawn()` or `spawnSync()` with `shell: true` on the same call line.
- `JSSEC005` (MEDIUM): conservative hardcoded credential-like assignments.

This is not complete JavaScript or TypeScript semantic analysis and does not validate JavaScript/TypeScript syntax. The lightweight lexical pass ignores comments and string literals and checks multiline dynamic calls, `spawn` shell options, and simple variable aliases of `child_process.exec`/`execSync`. Other aliases, template-literal expressions, framework-specific sinks, and complex syntax still require a real parser. Python uses AST checks plus bounded intra-file taint propagation for selected source/sink pairs; branch-sensitive and cross-module analysis is unsupported. The 12-fixture regression scores are not general accuracy estimates. See [scanner rule coverage](docs/SCANNER-RULES.md) and the [fixture benchmark](backend/reports/scanner-benchmark.json).

Java and Go are not currently advertised as supported. The scanner router is extension-based so future language modules can be added without changing the API or database contract.

## Windows Setup

From the repository root, use the existing virtual environment:

```powershell
backend\.venv\Scripts\python.exe -m uvicorn app.main:app --app-dir backend --reload
```

In a second terminal, start the frontend:

```powershell
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`. The Vite development proxy forwards API requests to `http://127.0.0.1:8000` by default. To use another API host, set `VITE_API_BASE_URL` before starting Vite:

```powershell
$env:VITE_API_BASE_URL = "http://127.0.0.1:8000"
npm run dev
```

## Public demo deployment

The API can run a restricted public demo when SECURCODE_DEMO_MODE=true. In this mode, POST /scan accepts only the bundled directory backend/app/api/docs/security-demo or its three tracked Python sample files; scans of any other workspace path return HTTP 403. Demo scans have a configurable SQLite-backed shared cooldown (10 seconds by default) and return HTTP 429 when a request arrives too soon. Read APIs are scoped to demo scans, and project, finding lifecycle, and incident writes are disabled. When demo mode is off, API resources require a database-backed bearer session. The demo does not accept user uploads or credentials, and it is not an authenticated service for scanning private repositories.

### Authentication setup

In private production, the bootstrap token is required only while the configured database has no accounts. Once bootstrap succeeds, remove it from the service environment; a restart with existing accounts does not require the token.

Generate `SECURCODE_BOOTSTRAP_TOKEN` with a cryptographically secure random generator (at least 32 characters) and deliver it through the deployment secret manager. Make a one-time `POST /auth/bootstrap` request with a username, password of at least 12 characters, and the token; store the returned administrator bearer token securely. Remove the bootstrap secret from the runtime environment immediately after setup. Rotate it by replacing the deployment secret before any future first-admin setup; bootstrap remains unavailable once an account exists. Use `POST /auth/login` for eight-hour sessions and `Authorization: Bearer <token>` for API calls. Administrators create accounts via `/auth/users`. Password changes and account disabling revoke affected sessions. Roles are `administrator`, `security_analyst`, `developer`, and `read_only`. The browser keeps its access token in memory and requires sign-in again after reload.

For local Windows setup, run `.\scripts\bootstrap-admin.ps1` from the repository root. It resolves `SECURCODE_DATABASE_PATH` using the same default and relative-path rules as the backend (the default is `backend\sentinelops.db`), refuses to proceed unless the existing database has zero accounts, creates a temporary random bootstrap secret for a loopback-only API process, prompts for credentials as secure input, verifies bootstrap and subsequent login, confirms both temporary sessions are revoked, and restores the shell environment. Use `.\scripts\bootstrap-admin.ps1 -WhatIf` for a read-only path/account-count check. The helper does not configure a hosted service; production bootstrap must use the deployment secret manager and the database path configured for that service.

### Deploy on Render

Use one Render Static Site for the frontend and one Render Web Service for the API. Both have free options. The free API sleeps after inactivity, can take about a minute to wake, and loses its SQLite file when it restarts or spins down. Treat history as temporary demo data. Private authenticated production requires an absolute `SECURCODE_DATABASE_PATH` whose parent is an existing mounted directory; the application cannot verify that the host provides durable storage. SQLite backups and restores remain operator procedures. A managed database would require a database adapter, which is not included. See [deployment and recovery](docs/DEPLOYMENT.md).

#### 1. Create the backend Web Service

In Render, choose New → Web Service, connect jeevakumarr48/SecurCode, and set:

- Name: securcode-demo-api (or another available name)
- Branch: main
- Root Directory: backend
- Runtime: Python 3
- Build Command: pip install -r requirements-deploy.txt
- Start Command: uvicorn app.main:app --host 0.0.0.0 --port $PORT
- Health Check Path: /healthz
- Instance Type: Free for a temporary demo

Add these environment variables:

- SECURCODE_ENV = production
- SECURCODE_DEMO_MODE = true
- SECURCODE_ALLOWED_ORIGINS = https://securcode-demo-web.onrender.com (reserve this planned static-site name; if Render assigns a different hostname, update this value)
- PYTHON_VERSION = 3.12.11

Wait for Render to finish deploying the API and verify https://securcode-demo-api.onrender.com/healthz returns a JSON response with status healthy. If you selected another available service name, use that hostname instead.

#### 2. Create the frontend Static Site

Choose New → Static Site, connect the same repository, and set:

- Name: securcode-demo-web (reserve this planned name for the backend CORS origin)
- Branch: main
- Root Directory: frontend
- Build Command: npm ci && npm run build
- Publish Directory: dist
- NODE_VERSION = 22.22.0

Set the build environment variable VITE_API_BASE_URL to the verified backend base URL, for example https://securcode-demo-api.onrender.com (no trailing slash). Deploy, then verify the site's exact HTTPS origin is https://securcode-demo-web.onrender.com and matches SECURCODE_ALLOWED_ORIGINS. If either hostname differs, update the corresponding environment variable and redeploy that service.

#### 3. Verify the public journey

Open the frontend HTTPS URL, confirm the API status is connected, and submit backend/app/api/docs/security-demo. The dashboard should report a completed scan with the bundled fixture findings and show that scan in history. A request for any other path should return HTTP 403. The /healthz endpoint is the backend health URL. On a free API instance, history is not durable and the first request after idle may be slow.

For local development, leave SECURCODE_ENV unset and continue using the existing Vite proxy. Production builds use VITE_API_BASE_URL; the frontend falls back to localhost only in Vite development mode.

## API

- `GET /status` returns backend health and service name.
- `POST /scan` accepts `{ "project_path": "backend/security_engine" }` or another relative file/directory path inside the workspace. It returns `status`, `total_findings`, `findings`, and `errors`. `completed` means every discovered supported source file was scanned; `partial` means at least one source file was scanned but one or more scan errors occurred; `failed` means no source file was scanned successfully after an error. These scan outcomes are represented in the response body; unexpected scanner exceptions return HTTP 500 after recording a failed history entry. Error and finding paths are workspace-relative, or redacted when outside the workspace; messages expose exception categories, not source contents or raw parser errors. Invalid or out-of-workspace paths are rejected with an HTTP error.
- `GET /history?limit=20` returns persisted scans, findings, and scan errors with workspace-relative or redacted paths. Partial and failed scan status is retained in SQLite. The limit must be between 1 and 100.
- `GET /stats` returns total scans, total findings, high-severity findings, and the latest scan.
- `GET /dashboard` returns current per-fingerprint severity and remediation counts, recent activity, affected projects, incident summary, trends, and a documented risk posture index.
- `GET /projects`, `POST /projects`, `GET /projects/{id}`, `PATCH /projects/{id}`, and `POST /projects/{id}/scan` provide project registration and local workspace scan workflows. Project paths must already exist inside the workspace. A registered repository URL is metadata only; remote repositories are not fetched or scanned.
- `GET /findings` supports status, severity, language, text search, project filtering, and pagination. `GET /findings/{scan_id}/{finding_index}` includes status history and related incidents. `PATCH /findings/{scan_id}/{finding_index}/status` persists lifecycle changes.
- `GET /scans/{scan_id}/comparison` compares findings with the prior scan for that project. A finding absent from a later scan is described as “no longer detected”; this does not verify remediation.
- `GET /incidents`, `POST /incidents`, `GET /incidents/{id}`, and `PATCH /incidents/{id}` manage incidents and related finding references.
- `GET /audit` provides paginated audit events. Audit metadata avoids status notes, descriptions, and source contents.
- `GET /audit/integrity` verifies the local audit hash chain and returns the first invalid event when tampering or corruption is detected.
- `GET /reports/summary` returns persisted posture data. `GET /reports/findings.csv` exports up to 200 findings and escapes spreadsheet formula prefixes.
- `GET /integrations/status` reports optional scanner availability. `POST /integrations/{tool}/scan` runs an available Semgrep, Bandit, Gitleaks, or Trivy scanner against a registered project; scanner calls are opt-in, timeout-bounded, and require PATH installation. Semgrep requires a local rules file via `SECURCODE_SEMGREP_CONFIG` and does not fetch rules automatically. `POST /integrations/sarif/import` imports normalized SARIF findings into a registered project's scan history.
- `GET /healthz` checks API and SQLite readiness.

Every finding includes `severity`, `confidence`, `test_id`, `language`, `filename`, `line_number`, `description`, a location-based `finding_id`, and rule-specific `remediation`. Selected Python and imported SARIF findings include CWE mappings; other mappings are limited to the documented rules. Existing stored findings without newer fields remain readable by the dashboard.

Finding IDs combine project path, language, rule ID, source filename, and line number. Status carries forward when the next scan reports the same location. A moved finding receives a new ID; there is no semantic code fingerprint yet. If a finding reappears after being marked Resolved, it returns to Open.

The dashboard risk posture index starts at 100 and subtracts 25 per current Critical, 10 per High, 4 per Medium, and 1 per Low Open or In Progress finding, floored at 0. Severity and lifecycle distributions use the latest observation per finding ID; scan totals remain historical totals. This index is a triage aid, not a breach probability or compliance score.

The application supports database-backed bearer sessions, four service roles, project memberships, and a restricted read-only public demo. Project creators receive membership; administrators may grant additional memberships through `POST /projects/{project_id}/members`. Non-administrators can use project-scoped project, scan, external-scanner, and SARIF routes only for projects they belong to. Until global aggregates are project-scoped, dashboard, history, statistics, findings search, audit, incidents, notifications, and reports are administrator-only. This is an early access-control implementation, not a fully hardened multi-tenant service.

See [GitHub integration status](docs/GITHUB-INTEGRATION.md) for the CodeQL workflow and the limits of local SARIF import.

## Example Scan

```powershell
Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:8000/scan `
  -ContentType "application/json" `
  -Body '{"project_path":"backend/security_engine"}'
```

Example findings include `SEC001` for `eval()`, `SEC002` for risky subprocess calls, `PYSEC003` for unsafe deserialization, and `JSSEC001` for JavaScript `eval()`.

## Testing And Validation

Run backend tests directly:

```powershell
cd backend
.venv\Scripts\python.exe -m pytest -q
```

Install the pinned development dependencies in a new environment with `python -m pip install -r requirements-dev.txt` from `backend`.

Run frontend unit tests and build the frontend:

```powershell
cd frontend
npm ci
npm test
npm run build
```

Run the browser acceptance workflow (requires the backend virtual environment and an installed Chrome or Edge browser on Windows):

```powershell
npm run test:e2e
```

The E2E test generates temporary credentials in memory, starts an isolated API with a disposable SQLite database, and exercises login, project registration with repository URL metadata, local scanning, findings, CSV download, and logout. It does not contact GitHub or clone the repository URL.

Run both checks with one command from the repository root:

```powershell
.\validate.ps1
```

The validation script stops and returns a failure if the backend suite, frontend unit tests, or frontend production build fails.

The API adds baseline security headers, but production still requires HTTPS termination with HSTS, suitable headers on the separately hosted frontend, durable mounted storage, operator-managed backup and restore, and a shared rate limiter before scaling workers. SQLite is the only supported application database; ephemeral hosting storage is not durable. See [security assumptions](docs/SECURITY.md) for the limits and operator procedures.

## CI Security Gate

The GitHub Actions workflow scans added, copied, modified, and renamed source files in each push or pull request. Deleted files are excluded; unsupported extensions and generated/minified files are skipped. Missing changed source files, invalid Python syntax, read failures, malformed scanner results, and scanner exceptions fail the gate instead of being treated as clean.

The default `SECURCODE_FAIL_ON_SEVERITY` threshold is `HIGH`: HIGH and CRITICAL findings fail the build, while MEDIUM and LOW findings are reported only if the threshold is lowered to include them. Configure the workflow environment to `CRITICAL`, `MEDIUM`, or `LOW` to adjust the threshold. Accepted values are `CRITICAL`, `HIGH`, `MEDIUM`, and `LOW`; invalid values fail the gate.

The gate uses the existing Python and JavaScript/TypeScript rules. It does not run source files, and its coverage and false-positive limitations remain as described below.

### Trivy Filesystem Scan

CI installs Trivy `v0.76.1` and runs `trivy fs` over the repository. The integration enables Trivy's vulnerability (`vuln`) and misconfiguration (`misconfig`) scanners, covering dependency manifests/lockfiles and supported IaC files. The intentionally vulnerable scanner demo fixtures are excluded from this repository-wide gate. Findings are normalized to SecurCode's finding fields and retain Trivy identifiers, target paths, severity, line/resource information, references, and available remediation details. Findings at or above `SECURCODE_FAIL_ON_SEVERITY` fail CI; the default is `HIGH`. Trivy execution failures, timeouts, invalid JSON, and unsupported severities fail closed.

After installation, CI also runs live integration tests against a temporary Terraform fixture using Trivy's `misconfig` scanner only. This confirms real JSON parsing and nonzero handling for a missing target without requiring the vulnerability database. Deterministic unit tests continue to use fixed fixture JSON.

For local use, install Trivy using the [official installation guide](https://trivy.dev/latest/getting-started/installation/), then run from the repository root:

```powershell
trivy --version
cd backend
.venv\Scripts\python.exe -m security_engine.trivy_scan .. --fail-on-severity HIGH
```

Use Trivy `v0.76.1` or a compatible release and ensure `trivy` is available on `PATH`. The command reports a clear error and exits nonzero if Trivy is missing.

Trivy is not currently bundled with SecurCode. It requires network access to fetch/update vulnerability data unless a Trivy cache is already available. Secret scanning is deliberately not enabled because the existing SecurCode rules already cover basic credential-like patterns; container/image and repository-history scans are not implemented in this integration.

## Optional AWS Assessment

The standalone AWS assessment uses boto3 read-only APIs and is not part of source scans, the API, file watcher, or CI gate. Install the optional, pinned SDK dependencies from the `backend` directory:

```powershell
python -m pip install -r requirements-aws.txt
```

Authenticate with an existing AWS SSO/profile setup or another supported AWS credential provider. Do not pass credentials to SecurCode. Without `--profile`, boto3 uses the standard credential chain. Run from the `backend` directory:

```powershell
python -m security_engine.aws_assessment --profile security-audit --region us-east-1
```

Repeat `--region` to assess more than one region. If omitted, the selected profile's configured default region is used. The command does not create, modify, or delete AWS resources.

The initial checks use `ListBuckets`, `GetBucketPolicyStatus`, `GetBucketAcl`, and `GetPublicAccessBlock` to report bucket policies classified as public, public or authenticated-user bucket ACL grants, and incomplete bucket-level public-access-block settings. This is not comprehensive S3 public-access analysis: it does not inspect object ACLs, access-point policies, account-level or organization-level public-access blocks, or determine effective access after all controls are combined. Security-group findings cover world-open all-protocol rules and TCP SSH/RDP or UDP RDP port ranges; other protocols/ports are not assessed. CloudTrail findings cover trail presence, logging state, and active multi-region coverage across the selected regions. Inventory calls follow AWS pagination tokens. These are configuration indicators, not proof of effective exploitability. Coverage is limited to the selected AWS profile and regions; it does not assess organization-wide controls or every AWS service.

The assessment requires these read-only IAM actions:

- `s3:ListAllMyBuckets`, `s3:GetBucketPolicyStatus`, `s3:GetBucketPublicAccessBlock`, `s3:GetBucketAcl`
- `ec2:DescribeSecurityGroups`
- `cloudtrail:DescribeTrails`, `cloudtrail:GetTrailStatus`

AWS may require `Resource: "*"` for list/describe actions; scope bucket-level S3 read actions to the assessed buckets where supported. Missing permissions and AWS API failures stop the assessment with an explicit error rather than a clean result. AWS SDK dependencies are excluded from the base requirements, so existing source scans continue to run without boto3 or AWS credentials.

## Limitations And False Positives

- JavaScript and TypeScript checks cannot resolve dataflow, framework-specific sinks, and all aliases or template-literal expressions.
- A credential-like constant may be a fixture or test value; placeholders are excluded, but review is still required.
- Dynamic SQL detection is intentionally limited to obvious f-strings, concatenation, formatting, and interpolation expressions.
- SQLite history defaults to `backend/sentinelops.db` and can be relocated with `SECURCODE_DATABASE_PATH`; the file is local application state and is ignored by Git without being deleted.
- Finding fingerprints use source locations, so line movement creates a new identity and project statuses are not user-assigned.
- Project-level membership is implemented for project routes, but membership removal, ownership transfer, and project-scoped aggregate reports/incidents/audit are not implemented. Those mixed/global endpoints are administrator-only.
- Login throttling is process-local; distributed rate limiting, MFA, account recovery, managed PostgreSQL, automated retention, and durable backup/restore orchestration are not implemented.
- Audit chaining is unkeyed and cannot prevent a database administrator from rewriting the SQLite file and recomputing the chain.
- The scanner reports risky patterns, not confirmed exploitable vulnerabilities. Findings require engineering review and remediation validation.

## Future Improvements

- Add project membership removal/transfer and scope incidents, audit, notifications, and aggregate reports before broad multi-user deployment.
- Add a real JavaScript/TypeScript parser when dependency and memory budgets allow it.
- Add finding-level remediation workflow automation and more detailed reports.
- Add tested Java and Go modules only when parser-backed rules are available.
- Add scan cancellation, pagination, and richer remediation metadata.
