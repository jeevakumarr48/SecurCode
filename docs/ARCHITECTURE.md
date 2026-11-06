# SecurCode architecture

## Runtime

- `backend/app/main.py` creates the FastAPI app, validates CORS configuration, applies bearer-session/project authorization and baseline API security headers, exposes database-backed readiness, and starts the lightweight demo-directory watcher.
- `backend/config.py` validates environment settings for demo mode, exact web origins, SQLite location, and scan resource limits. Private production requires an absolute database path whose parent directory already exists.
- `backend/app/api/routes.py` owns scan submission, scan history, health, statistics, path validation, and public path redaction.
- `backend/app/api/platform_routes.py` owns project management, finding lifecycle, audit queries, incidents, dashboard summaries, scan comparison, and CSV reporting.
- `backend/database.py` owns SQLite connections, additive schema initialization, scan persistence, findings state/comments, project records, incidents, status history, and hash-chained audit events.
- `backend/security_engine/scanner/` provides Python AST rules and bounded intra-file taint propagation, lightweight lexical JavaScript/TypeScript rules, bounded scan discovery, stable finding metadata, and remediation guidance.
- `backend/security_engine/integrations.py` provides opt-in Semgrep, Bandit, Gitleaks execution and SARIF normalization; Trivy remains in its dedicated adapter.
- `frontend/src/main.jsx` owns the responsive application shell and overview; `frontend/src/platformPages.jsx` contains the API-backed workflow pages.

The schema initializer applies idempotent additive changes at application startup and records schema versions 1 through 7. Existing scan rows are preserved, associated with project records, and given default Open finding state during migration. Version 2 adds finding comments and audit hash-chain fields; version 3 adds project metadata and notifications; version 6 redacts legacy sensitive audit metadata and rebuilds the chain; version 7 adds project memberships. Configure `SECURCODE_DATABASE_PATH` to select a different SQLite file. Back up that file before moving it or changing deployment storage.

## Finding identity and risk index

Finding IDs are SHA-256 fingerprints of project path, language, rule ID, source filename, and line number. This carries status across repeat scans when the finding remains at the same location. Moving code to a different line changes the ID; there is no semantic code fingerprint yet. A finding that is detected again after Resolved is reopened. Accepted Risk and False Positive states carry forward.

The dashboard severity and lifecycle distributions use the latest observation for each finding fingerprint. Scan and finding totals remain historical totals. The risk posture index starts at 100 and subtracts 25 per current Critical, 10 per High, 4 per Medium, and 1 per Low Open or In Progress finding, with a floor of 0. This is an operational triage index; it is not a probability of breach or a compliance score.

## Trust boundaries

- Scans inspect source and never execute it.
- API scan paths must be relative to the repository workspace and resolve inside it. Symbolic-link path components are rejected.
- Source file count, directory depth, per-file size, cumulative size, and elapsed time between files are bounded by configuration (`SECURCODE_MAX_SCAN_FILES`, `SECURCODE_MAX_SCAN_DEPTH`, `SECURCODE_MAX_SCAN_SECONDS`, `SECURCODE_MAX_SOURCE_FILE_BYTES`, `SECURCODE_MAX_SCAN_BYTES`). One source scan or directory walk already in progress cannot be interrupted. A process-local single-scan semaphore rejects concurrent built-in and external scans with HTTP 429.
- Public production demo mode is restricted to the bundled security demo, requires HTTPS CORS origins, applies a SQLite-backed shared cooldown, scopes read APIs to demo scans, and disables project, finding, and incident writes. The demo may use ephemeral storage but is not durable.
- Non-demo requests use database-backed opaque bearer sessions with administrator, security analyst, developer, and read-only role checks. One-time bootstrap requires a deployment secret of at least 32 characters. Project creators become members; administrators can grant membership. Non-administrator project, scan, finding, external-scanner, and SARIF routes are membership-scoped. Global dashboard, history, stats, finding search, audit, incidents, notifications, and reports are administrator-only until project-scoped implementations are available. Membership removal and ownership transfer are not implemented. Development mode should bind to loopback.
- API responses include baseline framing, MIME-sniffing, referrer, permissions, and Content Security Policy headers; the interactive docs routes omit CSP. HTTPS termination must enforce redirects and supply HSTS, and the separate frontend host must set its own policy. Login throttling and scan concurrency controls are process-local; private production is restricted by documented policy to one process and one replica. The application does not provide MFA, account recovery, automatic backups, or distributed rate limiting.
- Audit records are append-only through the API and linked by a SHA-256 hash chain verified at `/audit/integrity`. The unkeyed chain detects accidental or partial tampering; a database administrator can rewrite the entire chain, so it is not equivalent to remote immutable/WORM audit storage.

## Scanner coverage

Python checks use the standard-library AST with bounded intra-file taint propagation for selected sources and sinks. They resolve common import aliases and simple directly called function parameters. Branch-sensitive, inter-module and framework-complete analysis is unsupported. JavaScript and TypeScript checks mask comments and strings before matching calls; they remain lexical checks, not AST or taint analysis. See `docs/SCANNER-RULES.md` and the fixture benchmark JSON for declared boundaries and measured cases.

## Data behavior

Scan, status, incident, and audit records are stored in SQLite. Schema migrations 1-7 are additive and run during initialization. No automatic retention deletion or backup is enabled. The public free demo may lose its local database when its host restarts. Configure durable storage and operator-managed backups for local/private use; the current platform does not manage PostgreSQL or backups. See `docs/DEPLOYMENT.md` for online backup and isolated restore procedures.
