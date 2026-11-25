# SecurCode threat model

Scope: the multi-tenant platform (`/api/v1`, worker, web console, database, GitHub integration). Method: assets → trust boundaries → threats per actor (STRIDE categories in brackets) → mitigations with evidence → residual risk. Mitigations are implemented as described in [SECURITY-MODEL.md](SECURITY-MODEL.md) unless marked as residual.

## Assets

1. Customer source code (uploaded archives, GitHub tarballs, code snippets in findings).
2. Vulnerability data (findings, reviews, comments, reports), which is sensitive because it is a map of how to attack the customer.
3. Credentials: user passwords, sessions, MFA secrets, GitHub tokens, webhook secrets, the encryption key.
4. Tenant metadata: members, roles, policies, audit trail.
5. Platform availability: the API, the worker and the database.

## Trust boundaries

```
Internet ──► Edge (Vercel/nginx) ──► API ──► Database
                                     │        ▲
GitHub ──signed webhooks──► API      │        │
                                     ▼        │
                        Worker ──► Analyser subprocess (untrusted input)
                          │
                          └──► api.github.com / codeload.github.com
```

Untrusted input: everything from browsers, uploaded archives and repository contents, webhook payloads, SARIF imports, and GitHub API responses.

## Threats and mitigations

### Malicious users (authenticated or not)

| Threat | Mitigation | Evidence |
|---|---|---|
| Credential stuffing / brute force [S] | Per-IP and per-account rate limits, lockout, Argon2id, optional TOTP | `test_account_lockout_after_repeated_failures`, `test_login_rate_limited_per_identifier` |
| Account enumeration [I] | Uniform login/reset responses, dummy hash work, 404 for non-member orgs | `test_login_logout_and_generic_errors`, reset test |
| Session theft / fixation / replay [S] | HttpOnly+Secure cookie, rotation on login and MFA, idle and absolute expiry, revocation, hashed storage, TOTP counter replay check | `test_login_rotates_session_identifier`, `test_session_listing_and_revocation`, MFA replay assertion |
| CSRF [T] | Per-session synchroniser token on all unsafe methods, SameSite=Lax | `test_csrf_required_for_state_changing_requests` |
| XSS [T/I] | React escaping, no `dangerouslySetInnerHTML` in the console, CSP without `unsafe-inline` scripts, HTML reports escaped and served with `default-src 'none'` | `securityHeaders.test.js`, report CSP assertion |
| Privilege escalation inside an org [E] | Server-side permission matrix, owner-only privileged roles, last-owner protection, developer assignee checks, reviewer ≠ requester | role-matrix parametrised test, `test_admin_cannot_escalate_to_owner_or_demote_owner`, review tests |
| SQL injection [T] | SQLAlchemy parameter binding everywhere; sort/filter fields allowlisted | CodeQL, ruff `S608` clean for platform code |
| Spreadsheet formula injection via exports [T] | CSV values beginning `= + - @` are prefixed | `services/reports._csv_safe` |
| Abuse/resource exhaustion [D] | Body-size limits, per-org active-scan cap (20), rate-limited registration/invites/org creation, pagination caps | workflow and auth tests |

### Cross-tenant attackers

| Threat | Mitigation | Evidence |
|---|---|---|
| IDOR on any object [I/T] | Membership check per org, tenant-scoped loaders, 404 for everything foreign | OpenAPI-driven sweep of all 62 org routes, foreign-object sweep, unchanged-data check |
| Leaking via lists, exports, analytics, notifications, search [I] | Every query rooted in `org_id` + visible projects; notifications are per user | `test_foreign_object_ids_under_own_org_are_not_found` |
| Invitation token misuse [S/E] | Hashed, single-use, 7-day expiry, bound to the invited email, rotated on resend, revocable | `test_invitation_token_single_use_and_email_bound` |
| Platform admin snooping [I] | Admin role ≠ org membership; admin endpoints show aggregates only; every admin view audited | `test_platform_admin_is_not_an_org_member` |

### Malicious repositories and source archives

| Threat | Mitigation | Evidence |
|---|---|---|
| Path traversal / absolute paths / drive letters in archives [T/E] | Normalised relative paths, resolved-path containment, `O_EXCL|O_NOFOLLOW` writes | `test_zip_path_traversal_rejected` (5 variants), malicious-upload workflow test |
| Symlinks, hardlinks, device files [T/E] | Never extracted; reported as warnings | `test_tar_symlink_and_hardlink_and_device_not_extracted`, `test_zip_symlink_member_skipped` |
| Zip bombs / huge archives [D] | Member count, per-file and total size limits, compression-ratio check, streaming writes with counters | `test_zip_bomb_and_member_limits` |
| Code execution while scanning [E] | Code is never executed, imported or installed; analyser in `python -I` subprocess with empty cwd, minimal env (no secrets), rlimits (memory, CPU, file size, fds), wall-clock timeout, process-group kill | `test_scanner_subprocess_has_no_secrets_and_never_imports_scanned_code` |
| Parser DoS (pathological files) [D] | File-size limit, scan time limit, per-file exception isolation | scanner limit tests |
| Misleading "clean" result [T] | Partial or empty scans become `completed_with_warnings` and never auto-resolve | `test_scan_with_no_supported_files_is_not_clean`, `test_partial_scan_does_not_auto_resolve` |

### Credential theft

| Threat | Mitigation | Residual |
|---|---|---|
| Database dump [I] | Passwords Argon2id; session, reset and invite tokens stored as SHA-256; GitHub tokens, webhook secrets and TOTP secrets Fernet-encrypted with a key kept outside the DB | If the encryption key leaks together with a dump, integration tokens are exposed. Rotate tokens and the key. |
| Token exposure to browser [I] | GitHub tokens never returned (hint only); no tokens in web storage | — |
| Secrets in logs [I] | Audit metadata redaction; generic errors; no request bodies logged | Third-party log drains must be configured carefully |
| Secrets in repo [I] | gitignore, Trivy secret scan in CI, `.env.example` placeholders only | — |

### Unsafe scanning infrastructure / SSRF

| Threat | Mitigation |
|---|---|
| SSRF through GitHub integration [I] | Only `SECURCODE_GITHUB_API_URL` (HTTPS) and `codeload.github.com` are contacted. Redirects are followed manually and only to those hosts. Repository names and refs are validated with strict regexes. The token is never forwarded to the archive host. |
| SSRF through webhooks or user URLs [I] | The platform never fetches URLs supplied by users or webhook payloads. |
| Worker compromise via shared host [E] | Non-root container user, read-only root filesystem and `no-new-privileges` in compose, dropped capabilities, separate process from the API. |

### Unauthorised administrative actions

| Threat | Mitigation |
|---|---|
| Admin endpoint access [E] | `platform_admin` dependency. Admins are bootstrapped only via the CLI (`create-admin`), never via the API. |
| Silent admin actions [R] | Suspend, reactivate, disable and enable require a reason and are audited with `scope=platform`; even page views are audited. |
| Policy weakening [T/R] | Only owner, admin and security admin can change policy. Changes are versioned with a reason and audited, and notify other security administrators. |

### Webhook abuse

| Threat | Mitigation | Evidence |
|---|---|---|
| Forged events [S] | HMAC-SHA256 (`X-Hub-Signature-256`) with a per-integration secret, constant-time compare; unknown integration and bad signature return the same 401 | `test_webhook_signature_replay_and_pull_request_summary` |
| Replay / duplicate delivery [T] | Unique `X-GitHub-Delivery` ids stored; duplicates acknowledged without action; scan idempotency keys per commit | same test |
| Event flooding [D] | 5 MB body limit, active-scan cap per org, idempotency on `(project, PR, sha)` | — |
| PR blocking abuse [D] | PRs are never blocked unless the organisation sets `pr_fail_severity`; comments list only findings actually detected | `test_pr_threshold_policy_fails_status` |

### Resource exhaustion

Mitigations: upload, archive, member, extracted-size and per-file limits; scan timeouts; worker concurrency limit; per-org active scan cap; lease expiry with bounded retries; pagination maxima; DB-backed rate limits (the worker prunes rate-limit events older than 24 hours).

## Residual risks

1. **Process-level sandbox.** The analyser is isolated by interpreter flags and rlimits, not by a container or VM per scan. A memory-corruption bug in CPython's parser triggered by a crafted file could compromise the worker. Mitigation path: run the worker in a separate container or host with no database superuser rights and minimal network egress, or use gVisor/Firecracker.
2. **No PostgreSQL RLS.** A missed `org_id` filter in future code would not be caught by the database. The OpenAPI-driven isolation sweep in CI reduces this risk for new routes.
3. **PAT-based GitHub integration.** Tokens are user-scoped and long-lived. A GitHub App would give per-installation, short-lived, narrowly scoped tokens.
4. **Tamper-evident (not tamper-proof) audit log.** A DB superuser can rewrite the chain.
5. **Encryption key management.** There is a single Fernet key without built-in rotation tooling. `MultiFernet` rotation is on the roadmap.
6. **Rate limiting keyed on IP.** It is shared behind NAT and depends on correct proxy configuration.
7. **SMTP-less deployments.** Invitation links are shown once to the inviter and must be shared through a safe channel.
8. **No independent penetration test** has been performed.
