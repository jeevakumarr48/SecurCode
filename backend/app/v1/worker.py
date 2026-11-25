"""Background scan worker (run as a separate process from the API).

    python -m app.v1.worker            # long-running worker
    python -m app.v1.worker --once     # process queued work once and exit

Responsibilities: claim queued scans atomically (safe with several workers),
recover scans whose worker died (lease expiry, bounded retries), run due
scheduled scans exactly once, expire accepted risks, send due-date reminders
and record a heartbeat for health checks.
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import socket
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

from sqlalchemy import select, update

from security_engine.scanner.rules import SCANNER_VERSION

from . import audit
from .db import SessionLocal, utcnow
from .models import Finding, FindingEvent, FindingReview, Project, Scan, ScanSchedule, WorkerHeartbeat
from .services.common import notify, prune_rate_events
from .services.scanning import execute_scan, scope_key_for
from .services.schedule import next_run
from .settings import platform_settings

logger = logging.getLogger("securcode.v1.worker")
LEASE_SECONDS = 120
MAX_ATTEMPTS = 3


def claim_next_scan(worker_id: str) -> str | None:
    """Atomically move one queued scan to running. Returns its id or None."""
    with SessionLocal() as db:
        candidates = db.execute(
            select(Scan.id).where(Scan.status == "queued").order_by(Scan.created_at).limit(5)
        ).scalars().all()
        now = utcnow()
        for scan_id in candidates:
            result = db.execute(
                update(Scan)
                .where(Scan.id == scan_id, Scan.status == "queued")
                .values(status="running", lease_owner=worker_id, lease_expires_at=now + timedelta(seconds=LEASE_SECONDS),
                        started_at=now, attempts=Scan.attempts + 1, progress=5, progress_message="Claimed by worker")
            )
            if result.rowcount == 1:
                cancelled = db.execute(select(Scan.cancel_requested).where(Scan.id == scan_id)).scalar()
                if cancelled:
                    db.execute(update(Scan).where(Scan.id == scan_id).values(
                        status="cancelled", progress_message="Cancelled", finished_at=now, lease_owner=None))
                    db.commit()
                    continue
                db.commit()
                return scan_id
            db.rollback()
    return None


def renew_leases(worker_id: str, scan_ids) -> None:
    if not scan_ids:
        return
    with SessionLocal() as db:
        db.execute(
            update(Scan)
            .where(Scan.id.in_(list(scan_ids)), Scan.lease_owner == worker_id, Scan.status == "running")
            .values(lease_expires_at=utcnow() + timedelta(seconds=LEASE_SECONDS))
        )
        db.commit()


def recover_expired_leases() -> int:
    """Requeue (or fail after MAX_ATTEMPTS) scans whose worker stopped renewing."""
    now = utcnow()
    recovered = 0
    with SessionLocal() as db:
        stale = db.execute(
            select(Scan).where(Scan.status == "running", Scan.lease_expires_at.is_not(None), Scan.lease_expires_at < now)
        ).scalars().all()
        for scan in stale:
            if scan.attempts >= MAX_ATTEMPTS:
                scan.status = "failed"
                scan.error_message = "The scan worker stopped responding repeatedly; the scan was not completed."
                scan.finished_at = now
            else:
                scan.status = "queued"
                scan.progress = 0
                scan.progress_message = "Requeued after worker interruption"
            scan.lease_owner = None
            scan.lease_expires_at = None
            recovered += 1
        db.commit()
    return recovered


def run_due_schedules() -> int:
    """Create scans for schedules that are due. The optimistic update on
    next_run_at plus a unique idempotency key prevent duplicate execution even
    with several workers."""
    now = utcnow()
    created = 0
    with SessionLocal() as db:
        due = db.execute(
            select(ScanSchedule).where(ScanSchedule.enabled.is_(True), ScanSchedule.next_run_at.is_not(None),
                                       ScanSchedule.next_run_at <= now)
        ).scalars().all()
        for schedule in due:
            planned = schedule.next_run_at
            following = next_run(schedule, after=now)
            claimed = db.execute(
                update(ScanSchedule)
                .where(ScanSchedule.id == schedule.id, ScanSchedule.next_run_at == planned)
                .values(next_run_at=following, last_run_at=now)
            ).rowcount
            if claimed != 1:
                db.rollback()
                continue
            project = db.get(Project, schedule.project_id)
            key = f"schedule:{schedule.id}:{planned.isoformat()}"
            if project is None or project.status != "active" or db.execute(select(Scan.id).where(Scan.idempotency_key == key)).first():
                db.commit()
                continue
            from .routers.scans import latest_archive_id

            source = project.source_type
            archive_id = latest_archive_id(db, project) if source == "upload" else None
            if source == "upload" and archive_id is None:
                db.execute(update(ScanSchedule).where(ScanSchedule.id == schedule.id).values(
                    last_error="No uploaded archive to rescan."))
                notify(db, {schedule.created_by_id, project.owner_id}, "scan_failed",
                       f"Scheduled scan skipped: {project.name}", "Upload a source archive first.", None, project.org_id)
                db.commit()
                continue
            branch = schedule.branch or (project.default_branch if source == "github" else None)
            scan = Scan(org_id=project.org_id, project_id=project.id, trigger="scheduled", source_type=source,
                        archive_id=archive_id, branch=branch, scope_key=scope_key_for(source, branch, None),
                        requested_by_id=schedule.created_by_id, idempotency_key=key, config_json={"schedule_id": schedule.id})
            db.add(scan)
            db.flush()
            schedule.last_scan_id = scan.id
            schedule.last_error = None
            audit.record(db, "scan.scheduled_run", org_id=project.org_id, project_id=project.id, resource_type="scan", resource_id=scan.id,
                         metadata={"schedule_id": schedule.id})
            db.commit()
            created += 1
    return created


def expire_accepted_risks() -> int:
    now = utcnow()
    expired = 0
    with SessionLocal() as db:
        reviews = db.execute(
            select(FindingReview).where(FindingReview.kind == "accepted_risk", FindingReview.status == "approved",
                                        FindingReview.expires_at.is_not(None), FindingReview.expires_at < now)
        ).scalars().all()
        for review in reviews:
            finding = db.get(Finding, review.finding_id)
            review.status = "expired"
            if finding and finding.status == "accepted_risk":
                finding.status = "reopened"
                db.add(FindingEvent(org_id=finding.org_id, finding_id=finding.id, kind="status",
                                    body="Risk acceptance expired; finding reopened.", from_value="accepted_risk", to_value="reopened"))
                notify(db, {review.requested_by_id, finding.assignee_id}, "review_decision",
                       f"Risk acceptance expired: {finding.title}", "", f"/orgs/{finding.org_id}/findings/{finding.id}", finding.org_id)
            expired += 1
        db.commit()
    return expired


def remind_due_findings() -> int:
    """Notify assignees once when a finding is due within 3 days or overdue."""
    now = utcnow()
    count = 0
    with SessionLocal() as db:
        findings = db.execute(
            select(Finding).where(
                Finding.status.in_(["open", "triaged", "in_progress", "reopened"]), Finding.assignee_id.is_not(None),
                Finding.due_date.is_not(None), Finding.due_date <= now + timedelta(days=3),
            )
        ).scalars().all()
        for finding in findings:
            already = db.execute(
                select(FindingEvent.id).where(FindingEvent.finding_id == finding.id, FindingEvent.kind == "reminder",
                                              FindingEvent.created_at >= now - timedelta(days=7))
            ).first()
            if already:
                continue
            state = "overdue" if finding.due_date < now else "due soon"
            notify(db, [finding.assignee_id], "remediation_due", f"Remediation {state}: {finding.title}",
                   f"Due {finding.due_date.date().isoformat()}", f"/orgs/{finding.org_id}/findings/{finding.id}", finding.org_id)
            db.add(FindingEvent(org_id=finding.org_id, finding_id=finding.id, kind="reminder", body=f"Reminder sent ({state})."))
            count += 1
        db.commit()
    return count


def heartbeat(worker_id: str, active: int) -> None:
    with SessionLocal() as db:
        beat = db.get(WorkerHeartbeat, worker_id)
        now = utcnow()
        if beat is None:
            db.add(WorkerHeartbeat(worker_id=worker_id, hostname=socket.gethostname()[:120], version=SCANNER_VERSION,
                                   started_at=now, last_seen_at=now, active_jobs=active))
        else:
            beat.last_seen_at = now
            beat.active_jobs = active
        db.commit()


def run_pending_once(worker_id: str = "once") -> list[str]:
    """Synchronously process everything currently queued (tests, CLI, cron)."""
    recover_expired_leases()
    run_due_schedules()
    statuses = []
    while True:
        scan_id = claim_next_scan(worker_id)
        if scan_id is None:
            break
        statuses.append(execute_scan(scan_id, worker_id))
    return statuses


class Worker:
    def __init__(self, concurrency: int):
        self.worker_id = f"{socket.gethostname()[:60]}-{os.getpid()}-{uuid.uuid4().hex[:6]}"
        self.concurrency = concurrency
        self.stop = threading.Event()
        self.active: dict[str, object] = {}
        self.lock = threading.Lock()

    def _run(self, scan_id: str) -> None:
        try:
            status = execute_scan(scan_id, self.worker_id)
            logger.info("scan finished", extra={"scan_id": scan_id, "status": status})
        finally:
            with self.lock:
                self.active.pop(scan_id, None)

    def serve(self) -> None:
        logger.info("worker started", extra={"worker_id": self.worker_id, "concurrency": self.concurrency})
        last_housekeeping = 0.0
        with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            while not self.stop.is_set():
                with self.lock:
                    active = set(self.active)
                heartbeat(self.worker_id, len(active))
                renew_leases(self.worker_id, active)
                if time.monotonic() - last_housekeeping > 30:
                    last_housekeeping = time.monotonic()
                    try:
                        recover_expired_leases()
                        run_due_schedules()
                        expire_accepted_risks()
                        remind_due_findings()
                        with SessionLocal() as db:
                            prune_rate_events(db)
                            db.commit()
                    except Exception:  # noqa: BLE001 - housekeeping must not kill the worker
                        logger.exception("housekeeping failed")
                while len(active) < self.concurrency and not self.stop.is_set():
                    scan_id = claim_next_scan(self.worker_id)
                    if scan_id is None:
                        break
                    with self.lock:
                        self.active[scan_id] = pool.submit(self._run, scan_id)
                        active = set(self.active)
                self.stop.wait(2.0)
            logger.info("worker stopping; waiting for %d active scan(s)", len(self.active))


def main() -> None:  # pragma: no cover - process entry point
    parser = argparse.ArgumentParser(description="SecurCode scan worker")
    parser.add_argument("--once", action="store_true", help="process queued work and exit")
    parser.add_argument("--concurrency", type=int, default=platform_settings.worker_concurrency)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    if args.once:
        print({"processed": run_pending_once()})
        return
    worker = Worker(max(1, min(args.concurrency, 32)))

    def shutdown(*_):
        worker.stop.set()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    worker.serve()


if __name__ == "__main__":  # pragma: no cover
    main()
