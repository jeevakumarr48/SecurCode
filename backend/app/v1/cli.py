"""Operational commands.

    python -m app.v1.cli migrate                 # back up SQLite (if used), then alembic upgrade head
    python -m app.v1.cli create-admin EMAIL      # create or promote a platform administrator (prompts for password)
    python -m app.v1.cli import-legacy [--org-name NAME]
    python -m app.v1.cli verify-audit
    python -m app.v1.cli seed-demo               # clearly labelled demo organisation

Passwords are read interactively (getpass) or from SECURCODE_ADMIN_PASSWORD,
never from command-line arguments, so they do not end up in shell history.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import inspect, select

from . import audit
from .db import SessionLocal, engine, utcnow
from .models import Finding, Membership, Organization, Project, Scan, ScanFinding, User
from .security import hash_password, validate_password_policy
from .services.policy import ensure_policy
from .settings import platform_settings

BACKEND_DIR = Path(__file__).resolve().parents[2]


def _alembic_config() -> Config:
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    return config


def backup_sqlite() -> Path | None:
    if not platform_settings.is_sqlite:
        return None
    path = Path(platform_settings.database_url.split("sqlite:///", 1)[1])
    if not path.exists():
        return None
    target_dir = BACKEND_DIR.parent / "backups"
    target_dir.mkdir(exist_ok=True)
    target = target_dir / f"{path.stem}-pre-migration-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.db"
    # Use SQLite's online backup API so a consistent copy is taken even if the app is running.
    source = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    destination = sqlite3.connect(target)
    with destination:
        source.backup(destination)
    source.close()
    destination.close()
    check = sqlite3.connect(target).execute("PRAGMA integrity_check").fetchone()[0]
    if check != "ok":
        raise SystemExit(f"Backup integrity check failed: {check}")
    return target


def cmd_migrate(_args) -> None:
    backup = backup_sqlite()
    if backup:
        print(f"SQLite backup written to {backup}")
    command.upgrade(_alembic_config(), "head")
    print("Migrations applied.")


def _password_from_env_or_prompt() -> str:
    password = os.getenv("SECURCODE_ADMIN_PASSWORD")
    if password:
        return password
    first = getpass.getpass("New password: ")
    if first != getpass.getpass("Repeat password: "):
        raise SystemExit("Passwords did not match.")
    return first


def cmd_create_admin(args) -> None:
    email = args.email.strip().lower()
    with SessionLocal() as db:
        user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
        if user is None:
            password = _password_from_env_or_prompt()
            validate_password_policy(password, email)
            user = User(email=email, display_name=email.split("@")[0], password_hash=hash_password(password),
                        is_platform_admin=True, email_verified_at=utcnow(), password_changed_at=utcnow())
            db.add(user)
            action = "created"
        else:
            user.is_platform_admin = True
            action = "promoted"
        db.flush()
        audit.record(db, "admin.platform_admin_bootstrapped", actor=user, resource_type="user", resource_id=user.id,
                     metadata={"action": action, "via": "cli"}, scope="platform")
        db.commit()
    print(f"Platform administrator {action}: {email}")


def cmd_import_legacy(args) -> None:
    """Copy the legacy single-tenant data into a default organisation.

    Additive and idempotent: legacy tables are only read, never modified. The
    legacy administrator keeps their password (scrypt hash is accepted and
    upgraded to Argon2id at first login) and signs in with their old username.
    """
    if not platform_settings.is_sqlite:
        raise SystemExit("Legacy import reads the SQLite database configured by SECURCODE_DATABASE_PATH.")
    tables = set(inspect(engine).get_table_names())
    if "auth_users" not in tables:
        print("No legacy tables found; nothing to import.")
        return
    from .services.scanning import compute_fingerprint

    summary = {"users": 0, "projects": 0, "scans": 0, "findings": 0}
    with SessionLocal() as db:
        raw = db.connection().connection.driver_connection
        raw.row_factory = sqlite3.Row
        legacy_users = raw.execute("SELECT id, username, password_salt, password_hash, role, disabled, created_at FROM auth_users").fetchall()
        org = db.execute(select(Organization).where(Organization.slug == "legacy-workspace")).scalar_one_or_none()
        if org is None:
            org = Organization(name=args.org_name, slug="legacy-workspace")
            db.add(org)
            db.flush()
            ensure_policy(db, org.id)
        role_map = {"administrator": "owner", "security_analyst": "security_analyst", "developer": "developer", "read_only": "viewer"}
        for row in legacy_users:
            user = db.execute(select(User).where(User.legacy_user_id == row["id"])).scalar_one_or_none()
            if user is None:
                username = row["username"]
                email = username.lower() if "@" in username else f"{username.lower()}@legacy.securcode.invalid"
                user = User(email=email, display_name=username, legacy_user_id=row["id"], legacy_username=username,
                            password_hash=f"scrypt${row['password_salt']}${row['password_hash']}",
                            is_active=not row["disabled"], is_platform_admin=row["role"] == "administrator")
                db.add(user)
                db.flush()
                summary["users"] += 1
            if db.execute(select(Membership.id).where(Membership.org_id == org.id, Membership.user_id == user.id)).first() is None:
                db.add(Membership(org_id=org.id, user_id=user.id, role=role_map.get(row["role"], "viewer")))
        if "projects" in tables:
            for row in raw.execute("SELECT id, name, project_path, description, repository_url, default_branch FROM projects").fetchall():
                project = db.execute(select(Project).where(Project.org_id == org.id, Project.legacy_project_id == row["id"])).scalar_one_or_none()
                if project is None:
                    project = Project(org_id=org.id, name=row["name"][:120], slug=f"legacy-{row['id']}", legacy_project_id=row["id"],
                                      description=(row["description"] or "")[:2000] + "\n\nImported from the legacy console.",
                                      source_type="upload", repository_url=row["repository_url"], default_branch=row["default_branch"] or "main")
                    db.add(project)
                    db.flush()
                    summary["projects"] += 1
                    scan_rows = raw.execute(
                        "SELECT id, status, findings_json, created_at FROM scans WHERE project_id = ? ORDER BY id", (row["id"],)
                    ).fetchall() if "project_id" in {c[1] for c in raw.execute("PRAGMA table_info(scans)")} else []
                    for scan_row in scan_rows:
                        created = datetime.fromisoformat(scan_row["created_at"].replace("Z", "+00:00"))
                        if created.tzinfo is None:
                            created = created.replace(tzinfo=timezone.utc)
                        status = {"completed": "completed", "partial": "completed_with_warnings"}.get(scan_row["status"], "failed")
                        scan = Scan(org_id=org.id, project_id=project.id, status=status, trigger="import", source_type="legacy",
                                    scope_key="legacy", created_at=created, started_at=created, finished_at=created, progress=100,
                                    progress_message="Imported from legacy console", scanner_version="legacy",
                                    warnings=[{"path": ".", "message": "Imported legacy scan; not used for fix verification."}])
                        db.add(scan)
                        db.flush()
                        summary["scans"] += 1
                        try:
                            items = json.loads(scan_row["findings_json"] or "[]")
                        except json.JSONDecodeError:
                            items = []
                        for index, item in enumerate(items[:5000]):
                            rule_id = str(item.get("test_id", "legacy"))[:40]
                            path = str(item.get("filename", "unknown"))[-1000:]
                            fingerprint = compute_fingerprint(rule_id, path, str(item.get("line_number")), index)
                            finding = db.execute(select(Finding).where(Finding.project_id == project.id, Finding.scope_key == "legacy",
                                                                       Finding.fingerprint == fingerprint)).scalar_one_or_none()
                            severity = str(item.get("severity", "medium")).lower()
                            severity = severity if severity in {"critical", "high", "medium", "low", "info"} else "medium"
                            if finding is None:
                                finding = Finding(org_id=org.id, project_id=project.id, scope_key="legacy", fingerprint=fingerprint,
                                                  rule_id=rule_id, title=rule_id, description=str(item.get("description", ""))[:4000],
                                                  severity=severity, original_severity=severity,
                                                  confidence=str(item.get("confidence", "medium")).lower()[:10], file_path=path,
                                                  line=item.get("line_number"), status="open", first_scan_id=scan.id, last_scan_id=scan.id,
                                                  first_detected_at=created, last_detected_at=created, cwe=item.get("cwe"))
                                db.add(finding)
                                db.flush()
                                summary["findings"] += 1
                            db.add(ScanFinding(org_id=org.id, scan_id=scan.id, finding_id=finding.id, fingerprint=fingerprint,
                                               rule_id=rule_id, severity=severity, confidence=finding.confidence, file_path=path,
                                               line=item.get("line_number")))
                            db.flush()
        audit.record(db, "admin.legacy_imported", org_id=org.id, resource_type="organization", resource_id=org.id,
                     metadata=summary, scope="platform")
        db.commit()
    print(json.dumps({"organization": args.org_name, **summary}))
    print("Legacy users sign in with their previous username and password.")


def cmd_verify_audit(_args) -> None:
    with SessionLocal() as db:
        print(json.dumps(audit.verify_chain(db)))


def cmd_seed_demo(_args) -> None:
    with SessionLocal() as db:
        if db.execute(select(Organization).where(Organization.slug == "demo")).scalar_one_or_none():
            print("Demo organization already exists.")
            return
        password = os.getenv("SECURCODE_DEMO_PASSWORD")
        if not password:
            raise SystemExit("Set SECURCODE_DEMO_PASSWORD to create the demo account.")
        validate_password_policy(password)
        user = db.execute(select(User).where(User.email == "demo@securcode.example")).scalar_one_or_none()
        if user is None:
            user = User(email="demo@securcode.example", display_name="Demo Viewer", password_hash=hash_password(password),
                        email_verified_at=utcnow())
            db.add(user)
            db.flush()
        org = Organization(name="SecurCode Demo (sample data)", slug="demo", is_demo=True)
        db.add(org)
        db.flush()
        ensure_policy(db, org.id)
        db.add(Membership(org_id=org.id, user_id=user.id, role="security_analyst"))
        project = Project(org_id=org.id, name="Demo vulnerable app", slug="demo-vulnerable-app", source_type="fixture",
                          fixture_name="demo-vulnerable-app", description="Intentionally vulnerable sample code (demo data).",
                          owner_id=user.id)
        db.add(project)
        db.flush()
        db.add(Scan(org_id=org.id, project_id=project.id, source_type="fixture", trigger="manual", requested_by_id=user.id))
        db.commit()
    print("Demo organization created; run the worker to scan the fixture.")


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m app.v1.cli")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("migrate").set_defaults(func=cmd_migrate)
    admin = sub.add_parser("create-admin")
    admin.add_argument("email")
    admin.set_defaults(func=cmd_create_admin)
    legacy = sub.add_parser("import-legacy")
    legacy.add_argument("--org-name", default="Legacy workspace")
    legacy.set_defaults(func=cmd_import_legacy)
    sub.add_parser("verify-audit").set_defaults(func=cmd_verify_audit)
    sub.add_parser("seed-demo").set_defaults(func=cmd_seed_demo)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
    sys.exit(0)
