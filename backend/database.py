
import hashlib
import json
import re
import sqlite3
from pathlib import Path
from datetime import datetime, timezone
from config import settings

DATABASE_PATH = settings.database_path


def get_connection():
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 10000")
    return connection


def initialize_database():
    with get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_path TEXT NOT NULL,
                status TEXT NOT NULL,
                total_findings INTEGER NOT NULL,
                findings_json TEXT NOT NULL,
                errors_json TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL DEFAULT (
                    strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                )
            )
        """)
        columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(scans)")
        }
        if "errors_json" not in columns:
            connection.execute(
                "ALTER TABLE scans ADD COLUMN errors_json TEXT NOT NULL DEFAULT '[]'"
            )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC, id DESC)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_scans_project_path ON scans(project_path)")
        connection.executescript("""
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
            );
            CREATE TABLE IF NOT EXISTS projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                project_path TEXT NOT NULL UNIQUE,
                description TEXT NOT NULL DEFAULT '',
                owner TEXT,
                repository_url TEXT,
                default_branch TEXT NOT NULL DEFAULT 'main',
                settings_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
            );
            CREATE TABLE IF NOT EXISTS finding_states (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                finding_index INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'Open' CHECK(status IN ('Open','In Progress','Resolved','Accepted Risk','False Positive')),
                assignee TEXT,
                fingerprint TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                UNIQUE(scan_id, finding_index)
            );
            CREATE TABLE IF NOT EXISTS finding_status_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                finding_index INTEGER NOT NULL,
                from_status TEXT NOT NULL,
                to_status TEXT NOT NULL,
                actor TEXT NOT NULL,
                note TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
            );
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                outcome TEXT NOT NULL DEFAULT 'success',
                metadata_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                previous_hash TEXT NOT NULL DEFAULT '',
                event_hash TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS demo_scan_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at_epoch REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                recipient TEXT NOT NULL DEFAULT 'local-operator',
                event_key TEXT NOT NULL,
                category TEXT NOT NULL,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                href TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                read_at TEXT,
                UNIQUE(recipient, event_key)
            );
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                priority TEXT NOT NULL DEFAULT 'Medium' CHECK(priority IN ('Critical','High','Medium','Low')),
                severity TEXT NOT NULL DEFAULT 'Medium' CHECK(severity IN ('Critical','High','Medium','Low')),
                status TEXT NOT NULL DEFAULT 'Open' CHECK(status IN ('Open','Investigating','Contained','Resolved','Closed')),
                owner TEXT,
                resolution_notes TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
            );
            CREATE TABLE IF NOT EXISTS incident_findings (
                incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
                scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                finding_index INTEGER NOT NULL,
                PRIMARY KEY(incident_id, scan_id, finding_index)
            );
            CREATE TABLE IF NOT EXISTS incident_activity (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                details_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
            );
            CREATE TABLE IF NOT EXISTS finding_comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                finding_index INTEGER NOT NULL,
                fingerprint TEXT NOT NULL DEFAULT '',
                actor TEXT NOT NULL,
                comment TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
            );
            CREATE INDEX IF NOT EXISTS idx_finding_comments_ref ON finding_comments(scan_id, finding_index, id);
            CREATE INDEX IF NOT EXISTS idx_finding_states_status ON finding_states(status, scan_id);
            CREATE INDEX IF NOT EXISTS idx_audit_events_created ON audit_events(created_at DESC, id DESC);
            CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status, updated_at DESC);
            CREATE INDEX IF NOT EXISTS idx_incident_findings_finding ON incident_findings(scan_id, finding_index);
            CREATE INDEX IF NOT EXISTS idx_notifications_recipient_read ON notifications(recipient, read_at, id DESC);
        """)
        finding_state_columns = {row["name"] for row in connection.execute("PRAGMA table_info(finding_states)")}
        if "fingerprint" not in finding_state_columns:
            connection.execute("ALTER TABLE finding_states ADD COLUMN fingerprint TEXT NOT NULL DEFAULT ''")
        scan_columns = {row["name"] for row in connection.execute("PRAGMA table_info(scans)")}
        if "project_id" not in scan_columns:
            connection.execute("ALTER TABLE scans ADD COLUMN project_id INTEGER REFERENCES projects(id)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_scans_project_id ON scans(project_id, id DESC)")
        connection.execute("INSERT OR IGNORE INTO projects(name, project_path) SELECT CASE WHEN project_path = '' THEN 'Workspace' ELSE project_path END, project_path FROM scans")
        connection.execute("UPDATE scans SET project_id = (SELECT id FROM projects WHERE projects.project_path = scans.project_path) WHERE project_id IS NULL")
        connection.execute("""
            INSERT OR IGNORE INTO finding_states(scan_id, finding_index)
            SELECT s.id, CAST(f.key AS INTEGER) FROM scans s, json_each(s.findings_json) f
        """)
        for scan in connection.execute("SELECT id, project_path, findings_json FROM scans"):
            try:
                findings = json.loads(scan["findings_json"])
            except (TypeError, json.JSONDecodeError):
                continue
            for index, finding in enumerate(findings):
                connection.execute(
                    "UPDATE finding_states SET fingerprint = ? WHERE scan_id = ? AND finding_index = ? AND fingerprint = ''",
                    (finding_fingerprint(scan["project_path"], finding), scan["id"], index),
                )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_finding_states_fingerprint ON finding_states(fingerprint, scan_id DESC)")
        connection.execute("INSERT OR IGNORE INTO schema_migrations(version) VALUES (1)")
        audit_columns = {row["name"] for row in connection.execute("PRAGMA table_info(audit_events)")}
        if "previous_hash" not in audit_columns:
            connection.execute("ALTER TABLE audit_events ADD COLUMN previous_hash TEXT NOT NULL DEFAULT ''")
        if "event_hash" not in audit_columns:
            connection.execute("ALTER TABLE audit_events ADD COLUMN event_hash TEXT NOT NULL DEFAULT ''")
        comment_columns = {row["name"] for row in connection.execute("PRAGMA table_info(finding_comments)")}
        if "fingerprint" not in comment_columns:
            connection.execute("ALTER TABLE finding_comments ADD COLUMN fingerprint TEXT NOT NULL DEFAULT ''")
        connection.execute("""
            UPDATE finding_comments SET fingerprint = (
                SELECT fingerprint FROM finding_states
                WHERE finding_states.scan_id = finding_comments.scan_id
                  AND finding_states.finding_index = finding_comments.finding_index
            ) WHERE fingerprint = ''
        """)
        connection.execute("CREATE INDEX IF NOT EXISTS idx_finding_comments_fingerprint ON finding_comments(fingerprint, id)")
        _backfill_audit_hashes(connection)
        connection.execute("INSERT OR IGNORE INTO schema_migrations(version) VALUES (2)")
        project_columns = {row["name"] for row in connection.execute("PRAGMA table_info(projects)")}
        for column, definition in (
            ("owner", "TEXT"),
            ("repository_url", "TEXT"),
            ("default_branch", "TEXT NOT NULL DEFAULT 'main'"),
            ("settings_json", "TEXT NOT NULL DEFAULT '{}'"),
        ):
            if column not in project_columns:
                connection.execute(f"ALTER TABLE projects ADD COLUMN {column} {definition}")
        connection.execute("INSERT OR IGNORE INTO schema_migrations(version) VALUES (3)")
        scan_columns = {row["name"] for row in connection.execute("PRAGMA table_info(scans)")}
        for column, definition in (
            ("branch_name", "TEXT"),
            ("commit_sha", "TEXT"),
            ("pull_request_number", "INTEGER"),
            ("source_url", "TEXT"),
        ):
            if column not in scan_columns:
                connection.execute(f"ALTER TABLE scans ADD COLUMN {column} {definition}")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_scans_commit ON scans(commit_sha, branch_name, id DESC)")
        connection.executescript("""
            CREATE TABLE IF NOT EXISTS auth_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL COLLATE NOCASE UNIQUE,
                password_salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('administrator','security_analyst','developer','read_only')),
                disabled INTEGER NOT NULL DEFAULT 0 CHECK(disabled IN (0,1)),
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
            );
            CREATE TABLE IF NOT EXISTS auth_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
                token_hash TEXT NOT NULL UNIQUE,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
            );
            CREATE TABLE IF NOT EXISTS project_members (
                project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                user_id INTEGER NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                PRIMARY KEY(project_id, user_id)
            );
            CREATE INDEX IF NOT EXISTS idx_auth_sessions_expiration ON auth_sessions(expires_at);
            CREATE INDEX IF NOT EXISTS idx_project_members_user ON project_members(user_id, project_id);
        """)
        connection.execute("INSERT OR IGNORE INTO schema_migrations(version) VALUES (4)")
        connection.execute("INSERT OR IGNORE INTO schema_migrations(version) VALUES (5)")
        if not connection.execute(
            "SELECT 1 FROM schema_migrations WHERE version = 6"
        ).fetchone():
            _redact_existing_audit_events(connection)
            connection.execute("INSERT INTO schema_migrations(version) VALUES (6)")
        connection.execute("INSERT OR IGNORE INTO schema_migrations(version) VALUES (7)")


def save_scan(project_path, result, git_metadata=None):
    git_metadata = git_metadata or {}
    with get_connection() as connection:
        connection.execute(
            "INSERT OR IGNORE INTO projects(name, project_path) VALUES (?, ?)",
            (Path(project_path).name or project_path, project_path),
        )
        project = connection.execute("SELECT id FROM projects WHERE project_path = ?", (project_path,)).fetchone()
        cursor = connection.execute(
            """
            INSERT INTO scans (
                project_path, status, total_findings, findings_json, errors_json, project_id,
                branch_name, commit_sha, pull_request_number, source_url
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                project_path,
                result["status"],
                result["total_findings"],
                json.dumps(result["findings"]),
                json.dumps(result.get("errors", [])),
                project["id"] if project else None,
                git_metadata.get("branch"),
                git_metadata.get("commit_sha"),
                git_metadata.get("pull_request_number"),
                git_metadata.get("source_url"),
            ),
        )
        scan_id = cursor.lastrowid
        for index, _finding in enumerate(result["findings"]):
            fingerprint = _finding.get("finding_id") or finding_fingerprint(project_path, _finding)
            previous = connection.execute("""
                SELECT fs.status, fs.assignee FROM finding_states fs
                JOIN scans s ON s.id = fs.scan_id
                WHERE fs.fingerprint = ? AND fs.scan_id <> ?
                ORDER BY fs.scan_id DESC LIMIT 1
            """, (fingerprint, scan_id)).fetchone()
            status = previous["status"] if previous else "Open"
            if status == "Resolved":
                status = "Open"
            connection.execute(
                "INSERT INTO finding_states(scan_id, finding_index, status, assignee, fingerprint) VALUES (?, ?, ?, ?, ?)",
                (scan_id, index, status, previous["assignee"] if previous else None, fingerprint),
            )
        scan_action = {
            "completed": "scan.completed",
            "partial": "scan.partial",
            "failed": "scan.failed",
        }.get(result["status"], "scan.recorded")
        record_audit_event(connection, "system", scan_action, "scan", str(scan_id), {
            "project_path": project_path,
            "status": result["status"],
            "total_findings": result["total_findings"],
            "project_id": project["id"] if project else None,
        }, outcome=result["status"])
        status_title = {"completed": "Scan completed", "partial": "Scan partially completed", "failed": "Scan failed"}.get(result["status"], "Scan recorded")
        create_notification(connection, "scan", f"scan:{scan_id}", status_title,
                            f"{project_path}: {result['status']} with {result['total_findings']} findings.", "/Scans")
        critical_count = sum(1 for finding in result["findings"] if str(finding.get("severity", "")).upper() == "CRITICAL")
        if critical_count:
            create_notification(connection, "critical_finding", f"critical:{scan_id}", "Critical findings detected",
                                f"Scan {scan_id} detected {critical_count} critical finding(s).", "/Vulnerabilities?severity=CRITICAL")
        return scan_id


def get_scan_history(limit=20, project_path_prefix=None):
    limit = max(1, min(int(limit), 100))

    where = " WHERE (project_path = ? OR project_path LIKE ?)" if project_path_prefix else ""
    parameters = [project_path_prefix, project_path_prefix.rstrip("/") + "/%"] if project_path_prefix else []
    with get_connection() as connection:
        rows = connection.execute(
            "SELECT * FROM scans" + where + " ORDER BY id DESC LIMIT ?",
            (*parameters, limit),
        ).fetchall()

    history = []
    scan_ids = [row["id"] for row in rows]
    state_map = {}
    if scan_ids:
        placeholders = ",".join("?" for _ in scan_ids)
        with get_connection() as connection:
            state_map = {
                (state["scan_id"], state["finding_index"]): dict(state)
                for state in connection.execute(
                    f"SELECT scan_id, finding_index, status, assignee, updated_at FROM finding_states WHERE scan_id IN ({placeholders})",
                    scan_ids,
                )
            }

    for row in rows:
        item = dict(row)
        item["findings"] = json.loads(item.pop("findings_json"))
        item["errors"] = json.loads(item.pop("errors_json"))
        for index, finding in enumerate(item["findings"]):
            state = state_map.get((item["id"], index), {})
            finding.setdefault("status", state.get("status", "Open"))
            finding.setdefault("assignee", state.get("assignee"))
        history.append(item)

    return history


def get_scan_statistics(project_path_prefix=None, include_incidents=True):
    scan_filter = " WHERE (s.project_path = ? OR s.project_path LIKE ?)" if project_path_prefix else ""
    scan_parameters = (project_path_prefix, project_path_prefix.rstrip("/") + "/%") if project_path_prefix else ()
    with get_connection() as connection:
        summary = connection.execute("""
            SELECT
                COUNT(*) AS total_scans,
                COALESCE(SUM(total_findings), 0) AS total_findings
            FROM scans s
        """ + scan_filter, scan_parameters).fetchone()

        latest = connection.execute("""
            SELECT s.id, s.project_path, s.status, s.total_findings, s.created_at
            FROM scans s
        """ + scan_filter + " ORDER BY s.id DESC LIMIT 1", scan_parameters).fetchone()

        latest_finding_cte = """
            WITH ranked AS (
                SELECT fs.scan_id, fs.finding_index, fs.status, fs.fingerprint,
                       ROW_NUMBER() OVER (
                           PARTITION BY fs.fingerprint
                           ORDER BY fs.scan_id DESC, fs.finding_index DESC
                       ) AS position
                FROM finding_states fs JOIN scans s ON s.id = fs.scan_id
        """ + scan_filter + ") "
        severity_counts = {row["severity"]: row["count"] for row in connection.execute(latest_finding_cte + """
            SELECT upper(json_extract(f.value, '$.severity')) AS severity, COUNT(*) AS count
            FROM ranked r JOIN scans s ON s.id = r.scan_id
            JOIN json_each(s.findings_json) f ON CAST(f.key AS INTEGER) = r.finding_index
            WHERE r.position = 1 GROUP BY upper(json_extract(f.value, '$.severity'))
        """, scan_parameters)}
        status_counts = {row["status"]: row["count"] for row in connection.execute(
            latest_finding_cte + "SELECT status, COUNT(*) AS count FROM ranked WHERE position = 1 GROUP BY status",
            scan_parameters,
        )}
        project_filter = " WHERE (p.project_path = ? OR p.project_path LIKE ?)" if project_path_prefix else ""
        projects_count = connection.execute("SELECT COUNT(*) AS count FROM projects p" + project_filter, scan_parameters).fetchone()["count"]
        recent = [dict(row) for row in connection.execute("""
            SELECT s.id, s.project_path, s.status, s.total_findings, s.created_at
            FROM scans s
        """ + scan_filter + " ORDER BY s.id DESC LIMIT 10", scan_parameters)]
        trends = [dict(row) for row in connection.execute("""
            SELECT substr(s.created_at, 1, 10) AS date, COUNT(*) AS scans,
                   COALESCE(SUM(s.total_findings), 0) AS findings
            FROM scans s
        """ + scan_filter + " GROUP BY substr(s.created_at, 1, 10) ORDER BY date DESC LIMIT 30", scan_parameters)]
        most_affected = [dict(row) for row in connection.execute("""
            SELECT p.id, p.name, p.project_path, COUNT(DISTINCT s.id) AS scans,
                   COALESCE(SUM(s.total_findings), 0) AS findings
            FROM projects p LEFT JOIN scans s ON s.project_id = p.id
        """ + project_filter + " GROUP BY p.id ORDER BY findings DESC, scans DESC, p.id LIMIT 5", scan_parameters)]
        open_severity_counts = {row["severity"]: row["count"] for row in connection.execute(latest_finding_cte + """
            SELECT upper(json_extract(f.value, '$.severity')) AS severity, COUNT(*) AS count
            FROM ranked r JOIN scans s ON s.id = r.scan_id
            JOIN json_each(s.findings_json) f ON CAST(f.key AS INTEGER) = r.finding_index
            WHERE r.position = 1 AND r.status IN ('Open', 'In Progress')
            GROUP BY upper(json_extract(f.value, '$.severity'))
        """, scan_parameters)}
        recent_incidents = [dict(row) for row in connection.execute("""
            SELECT id, title, priority, severity, status, updated_at
            FROM incidents ORDER BY updated_at DESC, id DESC LIMIT 5
        """)] if include_incidents else []

    return {
        "total_scans": summary["total_scans"],
        "total_findings": summary["total_findings"],
        "high_severity_findings": severity_counts.get("HIGH", 0) + severity_counts.get("CRITICAL", 0),
        "severity_counts": {severity: severity_counts.get(severity, 0) for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")},
        "finding_status_counts": status_counts,
        "projects_count": projects_count,
        "recent_scans": recent,
        "trends": list(reversed(trends)),
        "most_affected_projects": most_affected,
        "open_finding_severity_counts": {severity: open_severity_counts.get(severity, 0) for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")},
        "recent_incidents": recent_incidents,
        "latest_scan": dict(latest) if latest else None,
    }


def record_audit_event(connection, actor, action, resource_type, resource_id, metadata=None, outcome="success"):
    if not connection.in_transaction:
        connection.execute("BEGIN IMMEDIATE")
    created_at = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    metadata_json = json.dumps(redact_audit_metadata(metadata or {}), separators=(",", ":"), sort_keys=True)
    previous = connection.execute("SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1").fetchone()
    previous_hash = previous["event_hash"] if previous and previous["event_hash"] else "0" * 64
    event_hash = _audit_digest(previous_hash, actor, action, resource_type, str(resource_id), outcome, metadata_json, created_at)
    connection.execute(
        "INSERT INTO audit_events(actor, action, resource_type, resource_id, outcome, metadata_json, created_at, previous_hash, event_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (actor, action, resource_type, str(resource_id), outcome, metadata_json, created_at, previous_hash, event_hash),
    )


_SENSITIVE_AUDIT_FIELDS = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "credential",
    "authorization",
    "cookie",
    "salt",
    "hash",
)


def redact_audit_metadata(value):
    """Redact secret-bearing fields before audit persistence or serialization."""
    if isinstance(value, dict):
        redacted = {}
        for key, item in value.items():
            normalized_key = re.sub(r"[^a-z0-9]", "", str(key).lower())
            if any(field in normalized_key for field in _SENSITIVE_AUDIT_FIELDS):
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = redact_audit_metadata(item)
        return redacted
    if isinstance(value, list):
        return [redact_audit_metadata(item) for item in value]
    if isinstance(value, tuple):
        return [redact_audit_metadata(item) for item in value]
    return value


def _redact_existing_audit_events(connection):
    changed = False
    rows = connection.execute("SELECT id, metadata_json FROM audit_events ORDER BY id").fetchall()
    for row in rows:
        try:
            metadata = json.loads(row["metadata_json"])
        except (TypeError, json.JSONDecodeError):
            continue
        redacted = redact_audit_metadata(metadata)
        encoded = json.dumps(redacted, separators=(",", ":"), sort_keys=True)
        if encoded != row["metadata_json"]:
            connection.execute(
                "UPDATE audit_events SET metadata_json = ? WHERE id = ?",
                (encoded, row["id"]),
            )
            changed = True
    if changed:
        previous_hash = "0" * 64
        for row in connection.execute("SELECT * FROM audit_events ORDER BY id"):
            event_hash = _audit_digest(
                previous_hash,
                row["actor"],
                row["action"],
                row["resource_type"],
                row["resource_id"],
                row["outcome"],
                row["metadata_json"],
                row["created_at"],
            )
            connection.execute(
                "UPDATE audit_events SET previous_hash = ?, event_hash = ? WHERE id = ?",
                (previous_hash, event_hash, row["id"]),
            )
            previous_hash = event_hash


def create_notification(connection, category, event_key, title, message, href, recipient="local-operator"):
    connection.execute(
        "INSERT OR IGNORE INTO notifications(recipient, event_key, category, title, message, href) VALUES (?, ?, ?, ?, ?, ?)",
        (recipient, event_key, category, title[:160], message[:500], href[:300]),
    )


def _audit_digest(previous_hash, actor, action, resource_type, resource_id, outcome, metadata_json, created_at):
    record = [previous_hash, actor, action, resource_type, resource_id, outcome, metadata_json, created_at]
    return hashlib.sha256(json.dumps(record, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()


def _backfill_audit_hashes(connection):
    previous_hash = "0" * 64
    rows = connection.execute("SELECT * FROM audit_events ORDER BY id").fetchall()
    for row in rows:
        stored = row["event_hash"]
        if stored:
            previous_hash = stored
            continue
        event_hash = _audit_digest(previous_hash, row["actor"], row["action"], row["resource_type"],
                                   row["resource_id"], row["outcome"], row["metadata_json"], row["created_at"])
        connection.execute("UPDATE audit_events SET previous_hash = ?, event_hash = ? WHERE id = ?",
                           (previous_hash, event_hash, row["id"]))
        previous_hash = event_hash


def verify_audit_chain(connection=None):
    owns_connection = connection is None
    if owns_connection:
        connection = get_connection()
    try:
        previous_hash = "0" * 64
        for row in connection.execute("SELECT * FROM audit_events ORDER BY id"):
            expected = _audit_digest(previous_hash, row["actor"], row["action"], row["resource_type"],
                                     row["resource_id"], row["outcome"], row["metadata_json"], row["created_at"])
            if row["previous_hash"] != previous_hash or row["event_hash"] != expected:
                return {"valid": False, "event_id": row["id"]}
            previous_hash = expected
        return {"valid": True, "event_id": None}
    finally:
        if owns_connection:
            connection.close()


def finding_fingerprint(project_path, finding):
    """Stable identifier for a rule occurrence at one project source location."""
    fields = (
        str(project_path).replace("\\", "/"),
        str(finding.get("language", "Unknown")).lower(),
        str(finding.get("test_id", "Unknown")),
        str(finding.get("filename", "")).replace("\\", "/"),
        str(finding.get("line_number", "")),
    )
    return hashlib.sha256("\0".join(fields).encode("utf-8", errors="replace")).hexdigest()
