# SecurCode

SecurCode is a lightweight, local-first static application security testing (SAST) tool. It scans source files without executing them, persists scan history in SQLite, and presents the results in a React/Vite security operations console.

## Architecture

- `backend/app/` contains the FastAPI application and REST routes.
- `backend/security_engine/scanner/engine.py` owns file discovery, language routing, skipped-directory policy, and duplicate suppression.
- `backend/security_engine/scanner/python.py` contains Python AST rules.
- `backend/security_engine/scanner/javascript.py` contains conservative JavaScript and TypeScript source-pattern rules.
- `backend/database.py` stores scan results and calculates aggregate statistics in SQLite.
- `frontend/` contains the React/Vite dashboard.

The scanner never executes source code. The API resolves every requested path inside the repository workspace, rejects absolute paths and traversal segments, and does not follow symlinked directories during discovery.

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

This is not complete JavaScript or TypeScript semantic analysis. Multi-line command options, aliases, framework-specific sinks, and deeply nested syntax require a real parser and are known limitations.

Java and Go are not currently advertised as supported. The scanner router is extension-based so future language modules can be added without changing the API or database contract.

## Windows Setup

From the repository root, use the existing virtual environment:

```powershell
backend\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --reload
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

## API

- `GET /status` returns backend health and service name.
- `POST /scan` accepts `{ "project_path": "backend/security_engine" }` or another relative file/directory path inside the workspace. It returns `status`, `total_findings`, and `findings`.
- `GET /history?limit=20` returns persisted scans and their findings. The limit must be between 1 and 100.
- `GET /stats` returns total scans, total findings, high-severity findings, and the latest scan.

Every finding includes `severity`, `confidence`, `test_id`, `language`, `filename`, `line_number`, and `description`. Existing stored findings without `language` remain readable by the dashboard as `Unknown`.

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

Build the frontend:

```powershell
cd frontend
npm run build
```

Run both checks with one command from the repository root:

```powershell
.\validate.ps1
```

The validation script stops and returns a failure if the backend suite or frontend production build fails.

## Limitations And False Positives

- Pattern-based JavaScript and TypeScript checks cannot resolve aliases, control flow, or multi-line syntax reliably.
- A credential-like constant may be a fixture or test value; placeholders are excluded, but review is still required.
- Dynamic SQL detection is intentionally limited to obvious f-strings, concatenation, formatting, and interpolation expressions.
- SQLite history is local to `backend/sentinelops.db`; the file is local application state and is ignored by Git without being deleted.
- The scanner reports risky patterns, not confirmed exploitable vulnerabilities. Findings require engineering review and remediation validation.

## Future Improvements

- Add a real JavaScript/TypeScript parser when dependency and memory budgets allow it.
- Add versioned database migrations and finding-level query APIs.
- Add tested Java and Go modules only when parser-backed rules are available.
- Add scan cancellation, pagination, and richer remediation metadata.
