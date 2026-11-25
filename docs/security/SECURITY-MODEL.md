# SecurCode security model

This document covers authentication, sessions, multi-tenant isolation, authorisation, auditing and secret handling for the `/api/v1` platform. The threat model is in [THREAT-MODEL.md](THREAT-MODEL.md).

## Authentication

| Control | Implementation |
|---|---|
| Password storage | Argon2id (`time_cost=3`, `memory_cost=19 MiB`, `parallelism=1`). Imported legacy scrypt hashes are accepted once and rehashed to Argon2id at the first successful login. |
| Password policy | 12–256 characters, a deny-list of common passwords, at least 5 distinct characters, must not contain the email name (NIST SP 800-63B style: length over composition rules). |
| Login | Identical message and comparable work (a dummy Argon2 verification) for unknown accounts and wrong passwords. |
| Brute force | DB-backed sliding windows (per IP: 30 attempts / 5 min; per account identifier: 10 / 5 min). They work across API replicas and are recorded in a separate transaction, so a failed request cannot roll the count back. Lockout after 8 failures for 15 minutes (configurable). |
| Sessions | 256-bit random opaque token in an `HttpOnly`, `Secure` (forced in production), `SameSite=Lax` cookie. Only its SHA-256 digest is stored. Absolute expiry 12 h and idle expiry 120 min (configurable). |
| Session fixation | Every login and MFA completion issues a new token and revokes any session presented with the request. |
| CSRF | Synchroniser token per session, required in `X-CSRF-Token` on every non-GET request (including logout and the MFA challenge). It is returned in the session payload and kept only in browser memory. |
| MFA | Optional TOTP (RFC 6238, 30 s, ±1 window). The secret is Fernet-encrypted at rest, and replay is prevented by storing the last accepted counter. A login with MFA enabled creates a 10-minute *pending* session that can only call `/auth/mfa/verify`. |
| Password reset | Single-use token (SHA-256 stored), 30-minute expiry. The same response is returned whether or not the account exists. A successful reset revokes all sessions. |
| Email verification | Single-use 48-hour token. Optional enforcement with `SECURCODE_REQUIRE_EMAIL_VERIFICATION=true`. Accepting an emailed invitation also proves control of the address. |
| Password change | Requires the current password and revokes every other session. |
| Account security page | Lists active sessions (device, IP, last activity), revokes one or all others, sets up or disables MFA, changes the password. |
| Tokens in the browser | None. No credential or token is written to `localStorage` or `sessionStorage` (a test asserts this). Only an invitation token is kept in `sessionStorage`, and only while the invitee signs up in that tab. |

## Multi-tenant isolation

1. Every organisation-owned row has `org_id` (FK, indexed); child rows (scan occurrences, events, reviews) duplicate it.
2. Every route under `/api/v1/organizations/{org_id}` depends on `org_context`, which loads the caller's membership for that exact org. Non-members get `404 Organization not found`, the same response as a non-existent org, so organisation ids cannot be enumerated.
3. Objects are loaded only through `get_project`, `get_scan` and `get_finding`, which filter by `id` **and** `org_id`. For developers and viewers they also require project membership.
4. List and export queries always start from `WHERE org_id = :ctx_org` plus the caller's visible-project set.
5. Platform administrators are **not** organisation members by virtue of their role and receive the same 404 on tenant routes.

Automated evidence (`backend/tests_v1/test_tenancy.py`):

- An attacker in organisation B calls **every** documented org-scoped route (62 method/path pairs, enumerated from OpenAPI) with organisation A's ids. Every call returns exactly `404`, and no response body contains tenant A's data.
- The attacker calls every object route under **their own** org id with A's object ids (project, scan, finding, invitation, review, schedule). All are rejected.
- After both sweeps, tenant A's data is verified unchanged.
- Listing, export and dashboard endpoints in B return nothing from A.
- Guessed ids, path-traversal strings and unauthenticated access are rejected.
- The browser E2E test repeats the check from a third user's real session.

Database-level row security (PostgreSQL RLS) is **not** enabled. Isolation is enforced in the application layer and covered by the tests above; see the roadmap.

## Roles and permissions

Organisation roles are separate from the platform-administrator flag. The matrix below is generated from `backend/app/v1/permissions.py`:

| Permission | owner | admin | security_admin | security_analyst | developer | viewer |
|---|---|---|---|---|---|---|
| `audit.view` | ✓ | ✓ | ✓ |  |  |  |
| `findings.comment` | ✓ | ✓ | ✓ | ✓ | ✓ |  |
| `findings.remediate` | ✓ | ✓ | ✓ | ✓ | ✓ |  |
| `findings.severity` | ✓ | ✓ | ✓ |  |  |  |
| `findings.triage` | ✓ | ✓ | ✓ | ✓ |  |  |
| `findings.view` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `integrations.manage` | ✓ | ✓ |  |  |  |  |
| `integrations.view` | ✓ | ✓ | ✓ | ✓ |  |  |
| `members.manage` | ✓ | ✓ |  |  |  |  |
| `members.manage_privileged` | ✓ |  |  |  |  |  |
| `members.view` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `org.archive` | ✓ |  |  |  |  |  |
| `org.update` | ✓ | ✓ |  |  |  |  |
| `org.view` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `policies.manage` | ✓ | ✓ | ✓ |  |  |  |
| `policies.view` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `projects.create` | ✓ | ✓ |  |  |  |  |
| `projects.delete` | ✓ | ✓ |  |  |  |  |
| `projects.manage` | ✓ | ✓ |  |  |  |  |
| `projects.view_all` | ✓ | ✓ | ✓ | ✓ |  |  |
| `reports.export` | ✓ | ✓ | ✓ | ✓ |  |  |
| `reports.view` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `reviews.approve` | ✓ | ✓ | ✓ |  |  |  |
| `reviews.request` | ✓ | ✓ | ✓ | ✓ |  |  |
| `scans.cancel` | ✓ | ✓ | ✓ | ✓ |  |  |
| `scans.run` | ✓ | ✓ | ✓ | ✓ |  |  |
| `schedules.manage` | ✓ | ✓ | ✓ |  |  |  |

Additional rules enforced in code:

- Only owners grant, change or revoke the `owner` and `admin` roles, and an organisation always keeps at least one owner.
- Developers can move only findings **assigned to them**, and only to `in_progress` or `fixed`.
- `resolved` is never set manually. Only a complete rescan sets it.
- When the policy requires review, `accepted_risk` and `false_positive` need approval from someone other than the requester. Risk acceptances expire (policy maximum 90 days by default), and the finding then reopens.
- Severity overrides require `findings.severity` and a written reason, and are recorded in the timeline and audit log.

## Audit logging

- `sc_audit_events` stores actor id and email, organisation, project, action, resource type and id, sanitised metadata, client IP, request correlation id and timestamp.
- Each event stores `sha256(canonical event + previous hash)`. `python -m app.v1.cli verify-audit` and the admin overview verify the chain; a test proves that editing an event breaks it. On PostgreSQL, appends are serialised with an advisory lock.
- Metadata keys containing `password`, `token`, `secret`, `credential`, `authorization`, `cookie`, `csrf` or `code` are replaced with `[redacted]`. Source code is never logged.
- No API route updates or deletes audit events (a test asserts that every audit route is `GET`).
- **Limitation:** the chain is tamper-evident, not tamper-proof. A database superuser could rewrite the whole chain. Export the chain head to external storage for stronger guarantees.

Recorded actions include `auth.login`, `auth.login_failed`, `auth.account_locked`, `auth.logout`, `auth.password_changed`, `auth.password_reset`, `auth.session_revoked`, `auth.mfa_*`, `org.created/updated/archived`, `member.invited/joined/role_changed/removed`, `project.created/updated/deleted/archive_uploaded`, `integration.connected/disconnected/credential_rotated`, `scan.requested/completed/failed/cancelled`, `finding.assigned/status_changed/risk_accepted/false_positive/severity_changed/review_*`, `policy.updated`, `report.exported` and `admin.*` (including every admin page view).

## Secrets

| Secret | Handling |
|---|---|
| Session tokens, reset, verification and invitation tokens | Only SHA-256 digests are stored. Invitation and reset links are delivered by email. Without SMTP, development prints them to the server console, and whenever an invitation email cannot be delivered the inviting administrator sees its link **once** in the API response. They are never written to logs in production. |
| GitHub tokens, webhook secrets, TOTP secrets | Fernet (AES-128-CBC + HMAC-SHA256) with `SECURCODE_ENCRYPTION_KEY`. Production refuses to start without the key. Tokens are never returned to the browser (only a `…last4` hint). |
| Code snippets | Values that look like secrets (`password = "…"`, AWS/GitHub/Slack/Stripe tokens, private-key headers) are redacted before storage. |
| Configuration | Only through environment variables. `.env` files, keys, databases and backups are gitignored, and CI runs a Trivy secret scan. |

## HTTP hardening

- API responses carry `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, a restrictive `Content-Security-Policy` and `X-Request-ID`.
- The web console (Vercel/nginx) uses a CSP with `script-src 'self' 'sha256-…'` (no `unsafe-inline` scripts; a test keeps the hash in sync), `frame-ancestors 'none'` and HSTS on Vercel.
- CORS allows only exact configured origins, with credentials.
- Body limits are 1 MB for JSON, the configured size for archive uploads and 5 MB for webhooks. Chunked request bodies are refused.
- OpenAPI and docs endpoints are disabled in production.
- Errors return generic messages with a `request_id`; stack traces are never returned.
- CSV exports neutralise spreadsheet formulas (CWE-1236).

## Known security limitations

See [THREAT-MODEL.md](THREAT-MODEL.md#residual-risks). The main ones:

- There is no PostgreSQL row-level security; isolation is application-enforced.
- The GitHub integration uses personal access tokens rather than a GitHub App.
- The scan sandbox is process-level (rlimits, isolated interpreter), not a container or VM per scan.
- The rate limiter keys on the client IP reported by the proxy, so its value depends on correct proxy configuration (`SECURCODE_TRUST_PROXY_HEADERS`).
- The application has not been independently penetration tested.
