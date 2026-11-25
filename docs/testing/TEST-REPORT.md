# Test report: multi-tenant platform release

Run on 2026-11-26 in a Linux workspace (Python 3.13, Node 22, PostgreSQL 16, Google Chrome headless). Every number below comes from a command that was actually executed. CI (`.github/workflows/platform-ci.yml`) repeats these checks on Python 3.12; that workflow has **not yet run on GitHub**, because the branch has not been pushed.

## Summary

| Check | Command | Result |
|---|---|---|
| Backend: full suite, legacy + platform (SQLite) | `cd backend && python -m pytest -q` | **251 passed, 2 skipped** |
| Platform suite on PostgreSQL 16 | `SECURCODE_TEST_DATABASE_URL=postgresql://… python -m pytest tests_v1 -q` | **60 passed** |
| Alembic (SQLite) | `alembic upgrade head && alembic check` | no drift |
| Alembic (PostgreSQL) | upgrade → check → downgrade base → upgrade | all succeeded, no drift |
| Migration on a copy of the real `sentinelops.db` | `cli migrate` + `cli import-legacy` (twice) | backup written; all 15 legacy tables and indexes identical before and after; import idempotent (1 user, 4 projects, 19 scans, 6 findings) |
| Lint (platform code, security rules) | `ruff check app/v1 … tests_v1` | clean |
| Lint (legacy, syntax and undefined names) | `ruff check . --select E9,F63,F7,F82` | clean |
| Frontend type check | `npm run typecheck` | clean |
| Frontend lint | `npm run lint` | clean |
| Frontend unit tests | `npm test` (node:test + Vitest) | **4 + 11 passed** |
| Frontend production build | `VITE_SAME_ORIGIN_API=true npm run build` | success; main chunk 115 kB (36 kB gzip), charts lazy-loaded |
| Browser end-to-end | `npm run test:e2e:platform` | **1 journey passed** (real API, worker and Chrome) |
| Scanner benchmark, extended rules | `python -m security_engine.benchmark_v2` | TP 41, FP 0, FN 0 (30 rules) |
| Scanner benchmark, original rules | `python -m security_engine.benchmark` | TP 15, FP 0, FN 0 |
| CI security gate over all changes | `python -m security_engine.ci_gate` | passed |
| Python dependency audit | `pip-audit -r requirements.txt --strict` | no known vulnerabilities |
| npm production dependency audit | `npm audit --omit=dev --audit-level=high` | 0 vulnerabilities |
| Secret scan | `trivy fs --scanners secret` (fixtures excluded) | no secrets |
| Dockerfile misconfiguration | `trivy config` (embedded checks) | 0 findings, both Dockerfiles |
| Container image build | — | **not run**: Docker Hub is blocked from this environment; CI builds and Trivy-scans the images |

## Backend test coverage by area

| Area | Tests (`backend/tests_v1/`) |
|---|---|
| Registration, login, logout, generic errors | `test_register_*`, `test_login_logout_and_generic_errors`, `test_duplicate_registration_rejected`, `test_weak_password_rejected` |
| Password hashing | `test_password_is_stored_with_argon2id`, `test_legacy_scrypt_hash_is_accepted_and_upgraded` |
| CSRF, session fixation, revocation | `test_csrf_required_*`, `test_login_rotates_session_identifier`, `test_session_listing_and_revocation`, `test_password_change_revokes_other_sessions` |
| Brute force | `test_account_lockout_after_repeated_failures`, `test_login_rate_limited_per_identifier` |
| Password reset | `test_password_reset_flow_is_single_use_and_revokes_sessions` |
| MFA | `test_totp_mfa_enrolment_and_login_challenge` (pending session, CSRF, replay) |
| Hardening | `test_security_headers_and_request_id`, `test_oversized_body_rejected` |
| Tenant isolation / IDOR | `test_every_org_route_rejects_foreign_org` (all 62 org routes → 404), `test_foreign_object_ids_under_own_org_are_not_found`, `test_foreign_tenant_data_unchanged_after_attack`, `test_guessed_ids_and_non_members`, `test_unauthenticated_requests_rejected` |
| Roles | `test_role_permission_matrix_is_enforced_server_side` (5 roles × 6 actions), `test_admin_cannot_escalate_to_owner_or_demote_owner`, `test_platform_admin_is_not_an_org_member` |
| Invitations, multiple orgs | `test_invitation_token_single_use_and_email_bound`, `test_user_can_belong_to_and_switch_between_orgs` |
| Audit | `test_audit_chain_records_actor_and_detects_tampering` |
| Scan lifecycle, findings, verification, comparison, exports | `test_full_vulnerability_lifecycle` (upload → background scan → 9 findings → assign → developer remediation → rescan → 7 verified fixed → comparison → recurrence → SARIF/CSV/HTML → dashboard) |
| Incomplete scans | `test_scan_with_no_supported_files_is_not_clean`, `test_partial_scan_does_not_auto_resolve`, `test_malicious_archive_fails_safely` |
| Upload validation, idempotency, cancellation | `test_non_archive_upload_rejected`, `test_cancel_queued_scan_and_idempotency` |
| Reviews, bulk operations | `test_risk_acceptance_requires_independent_review`, `test_bulk_assignment_and_filters` |
| Archive safety | 5 traversal variants, symlink/hardlink/device, zip symlink, zip bomb, member limit, duplicates, format sniffing |
| Scanner isolation | `test_scanner_subprocess_has_no_secrets_and_never_imports_scanned_code` |
| Fingerprints, benchmark | `test_fingerprint_stable_across_line_moves_and_whitespace`, `test_benchmark_v2_has_no_false_results` |
| GitHub (mocked API) | connect/list/branch scan, invalid and expired credentials, disconnect, webhook signature, replay, PR summary, PR threshold |
| Schedules, notifications, SARIF import | timezone/DST, exactly-once execution, read state and preferences, schema validation |

## Frontend tests

- `test-app/api.test.ts`: cookies are always sent; the CSRF header is sent only on unsafe methods; errors are parsed; query strings are serialised; no credentials are written to web storage.
- `test-app/app.test.tsx`: redirect to sign-in; full login with MFA challenge using the pending CSRF token; empty-state dashboard; role-based navigation for a developer; non-member organisation route; unread badge; finding detail offers only API-allowed transitions and requires justification for reviewed statuses.
- `test/securityHeaders.test.js`: the CSP script hash matches the inline script, and `unsafe-inline` scripts are never allowed.

## Browser end-to-end journey (`frontend/e2e-platform/journey.spec.ts`)

The test runs against the real FastAPI app, the real worker and a throwaway SQLite database, in Chrome:

1. Landing page.
2. Register the owner, create an organisation and a project.
3. Invite a developer; the one-time link is read from the UI.
4. Upload the vulnerable fixture and run the scan through the background worker until it completes with 9 findings.
5. The developer accepts the invitation and registers in a separate browser context.
6. The owner assigns the SQL-injection finding and triages it.
7. The developer moves it to *In progress*, comments and marks it *Fixed*; the developer UI offers no risk-acceptance option.
8. The owner uploads the fixed code and rescans: the finding is *resolved* and "Verified fixed by" the new scan.
9. The scan comparison reports equivalent scans with 7 resolved.
10. CSV export downloads.
11. An outsider in another organisation sees "Organization not found", and a direct `fetch` of the first organisation's findings returns **404**.

Screenshots captured by this run are in [`../screenshots/`](../screenshots/).

## Not tested or not verifiable here

- The GitHub integration against live github.com (needs a token): only mocked.
- SMTP delivery (needs a provider): only the no-SMTP path is tested.
- Container image builds and Trivy image scans: run in CI only.
- A public deployment: not performed. See the deployment guide.
- Python 3.14 on Windows was not executed here; dependencies publish wheels for it, but run the suite locally to confirm.
- Load and performance testing, and an independent penetration test.
