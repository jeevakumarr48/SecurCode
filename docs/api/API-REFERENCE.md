# SecurCode Platform API reference (/api/v1)

Generated from the FastAPI application (105 operations). The machine-readable OpenAPI 3 document is [`openapi-v1.json`](openapi-v1.json); in development the interactive docs are served at `/docs`.

Conventions: JSON bodies; cookie session authentication; `X-CSRF-Token` header on state-changing requests; errors are `{"detail": ..., "request_id": ...}`; list endpoints accept `limit`/`offset` and return `total`; organisation resources live under `/api/v1/organizations/{org_id}` and return 404 to non-members.

## analytics

| Method | Path | Summary |
|---|---|---|
| GET | `/api/v1/organizations/{org_id}/analytics/dashboard` | Dashboard |
| GET | `/api/v1/organizations/{org_id}/analytics/mttr` | Mean Time To Remediate |

## authentication

| Method | Path | Summary |
|---|---|---|
| POST | `/api/v1/auth/login` | Login |
| POST | `/api/v1/auth/logout` | Logout |
| PATCH | `/api/v1/auth/me` | Update Profile |
| POST | `/api/v1/auth/me/active-organization` | Set Active Org |
| POST | `/api/v1/auth/mfa/disable` | Mfa Disable |
| POST | `/api/v1/auth/mfa/enable` | Mfa Enable |
| POST | `/api/v1/auth/mfa/setup` | Mfa Setup |
| POST | `/api/v1/auth/mfa/verify` | Mfa Verify |
| POST | `/api/v1/auth/password/change` | Change Password |
| POST | `/api/v1/auth/password/forgot` | Forgot Password |
| POST | `/api/v1/auth/password/reset` | Reset Password |
| POST | `/api/v1/auth/register` | Register |
| GET | `/api/v1/auth/session` | Session Info |
| GET | `/api/v1/auth/sessions` | List Sessions |
| POST | `/api/v1/auth/sessions/revoke-others` | Revoke Other Sessions |
| DELETE | `/api/v1/auth/sessions/{session_id}` | Revoke Session |
| POST | `/api/v1/auth/verify-email` | Verify Email |
| POST | `/api/v1/auth/verify-email/resend` | Resend Verification |

## findings

| Method | Path | Summary |
|---|---|---|
| GET | `/api/v1/organizations/{org_id}/findings` | List Findings |
| POST | `/api/v1/organizations/{org_id}/findings/bulk` | Bulk Update |
| GET | `/api/v1/organizations/{org_id}/findings/{finding_id}` | Get Finding Detail |
| PATCH | `/api/v1/organizations/{org_id}/findings/{finding_id}` | Update Finding |
| POST | `/api/v1/organizations/{org_id}/findings/{finding_id}/comments` | Add Comment |
| POST | `/api/v1/organizations/{org_id}/findings/{finding_id}/reviews` | Request Review |
| GET | `/api/v1/organizations/{org_id}/reviews` | List Reviews |
| POST | `/api/v1/organizations/{org_id}/reviews/{review_id}/decision` | Decide Review |

## github

| Method | Path | Summary |
|---|---|---|
| GET | `/api/v1/organizations/{org_id}/integrations` | List Integrations |
| POST | `/api/v1/organizations/{org_id}/integrations/github` | Connect Github |
| DELETE | `/api/v1/organizations/{org_id}/integrations/{integration_id}` | Disconnect |
| PATCH | `/api/v1/organizations/{org_id}/integrations/{integration_id}` | Update Integration |
| GET | `/api/v1/organizations/{org_id}/integrations/{integration_id}/repositories` | Repositories |
| GET | `/api/v1/organizations/{org_id}/integrations/{integration_id}/repositories/{owner}/{repo}/branches` | Branches |
| POST | `/api/v1/organizations/{org_id}/integrations/{integration_id}/rotate` | Rotate Credential |
| POST | `/api/v1/webhooks/github/{integration_id}` | Github Webhook |

## health

| Method | Path | Summary |
|---|---|---|
| GET | `/api/v1/health/live` | Live |
| GET | `/api/v1/health/ready` | Ready |
| GET | `/api/v1/health/worker` | Worker |

## notifications

| Method | Path | Summary |
|---|---|---|
| GET | `/api/v1/notifications` | List Notifications |
| GET | `/api/v1/notifications/preferences` | Get Preferences |
| PUT | `/api/v1/notifications/preferences` | Set Preference |
| POST | `/api/v1/notifications/read-all` | Mark All Read |
| POST | `/api/v1/notifications/{notification_id}/read` | Mark Read |

## organizations

| Method | Path | Summary |
|---|---|---|
| POST | `/api/v1/invitations/accept` | Accept Invitation |
| POST | `/api/v1/invitations/preview` | Preview Invitation |
| GET | `/api/v1/organizations` | List My Organizations |
| POST | `/api/v1/organizations` | Create Organization |
| GET | `/api/v1/organizations/{org_id}` | Get Organization |
| PATCH | `/api/v1/organizations/{org_id}` | Update Organization |
| GET | `/api/v1/organizations/{org_id}/activity` | Team Activity |
| POST | `/api/v1/organizations/{org_id}/archive` | Archive Organization |
| GET | `/api/v1/organizations/{org_id}/invitations` | List Invitations |
| POST | `/api/v1/organizations/{org_id}/invitations` | Create Invitation |
| DELETE | `/api/v1/organizations/{org_id}/invitations/{invitation_id}` | Revoke Invitation |
| POST | `/api/v1/organizations/{org_id}/invitations/{invitation_id}/resend` | Resend Invitation |
| GET | `/api/v1/organizations/{org_id}/members` | List Members |
| DELETE | `/api/v1/organizations/{org_id}/members/{user_id}` | Remove Member |
| PATCH | `/api/v1/organizations/{org_id}/members/{user_id}` | Change Member Role |
| POST | `/api/v1/organizations/{org_id}/restore` | Restore Organization |
| GET | `/api/v1/permissions/matrix` | Get Permission Matrix |

## platform-admin

| Method | Path | Summary |
|---|---|---|
| GET | `/api/v1/admin/config` | Config |
| GET | `/api/v1/admin/jobs` | Jobs |
| GET | `/api/v1/admin/organizations` | Organizations |
| POST | `/api/v1/admin/organizations/{org_id}/reactivate` | Reactivate Org |
| POST | `/api/v1/admin/organizations/{org_id}/suspend` | Suspend Org |
| GET | `/api/v1/admin/overview` | Overview |
| GET | `/api/v1/admin/security-events` | Security Events |
| GET | `/api/v1/admin/users` | Users |
| POST | `/api/v1/admin/users/{user_id}/disable` | Disable User |
| POST | `/api/v1/admin/users/{user_id}/enable` | Enable User |

## policies

| Method | Path | Summary |
|---|---|---|
| GET | `/api/v1/organizations/{org_id}/audit-events` | List Audit Events |
| GET | `/api/v1/organizations/{org_id}/audit-events/export.csv` | Export Audit Events |
| GET | `/api/v1/organizations/{org_id}/policy` | Get Policy |
| PUT | `/api/v1/organizations/{org_id}/policy` | Put Policy |
| GET | `/api/v1/organizations/{org_id}/policy/history` | Policy History |
| GET | `/api/v1/rules` | List Rules |

## projects

| Method | Path | Summary |
|---|---|---|
| GET | `/api/v1/organizations/{org_id}/fixtures` | List Fixtures |
| GET | `/api/v1/organizations/{org_id}/projects` | List Projects |
| POST | `/api/v1/organizations/{org_id}/projects` | Create Project |
| DELETE | `/api/v1/organizations/{org_id}/projects/{project_id}` | Delete Project |
| GET | `/api/v1/organizations/{org_id}/projects/{project_id}` | Get Project Detail |
| PATCH | `/api/v1/organizations/{org_id}/projects/{project_id}` | Update Project |
| GET | `/api/v1/organizations/{org_id}/projects/{project_id}/activity` | Project Activity |
| POST | `/api/v1/organizations/{org_id}/projects/{project_id}/archive` | Archive Project |
| GET | `/api/v1/organizations/{org_id}/projects/{project_id}/archives` | List Archives |
| POST | `/api/v1/organizations/{org_id}/projects/{project_id}/archives` | Upload Archive |
| POST | `/api/v1/organizations/{org_id}/projects/{project_id}/members` | Add Project Member |
| DELETE | `/api/v1/organizations/{org_id}/projects/{project_id}/members/{user_id}` | Remove Project Member |
| POST | `/api/v1/organizations/{org_id}/projects/{project_id}/restore` | Restore Project |

## reports

| Method | Path | Summary |
|---|---|---|
| GET | `/api/v1/organizations/{org_id}/exports/findings` | Export Findings |
| POST | `/api/v1/organizations/{org_id}/projects/{project_id}/sarif-import` | Import Sarif |
| GET | `/api/v1/organizations/{org_id}/reports/{kind}` | Security Report |

## scans

| Method | Path | Summary |
|---|---|---|
| POST | `/api/v1/organizations/{org_id}/projects/{project_id}/scans` | Start Scan |
| POST | `/api/v1/organizations/{org_id}/projects/{project_id}/scans/upload` | Upload And Scan |
| GET | `/api/v1/organizations/{org_id}/scans` | List Scans |
| GET | `/api/v1/organizations/{org_id}/scans/{scan_id}` | Get Scan Detail |
| POST | `/api/v1/organizations/{org_id}/scans/{scan_id}/cancel` | Cancel Scan |
| GET | `/api/v1/organizations/{org_id}/scans/{scan_id}/compare/{other_scan_id}` | Compare |
| GET | `/api/v1/organizations/{org_id}/scans/{scan_id}/findings` | Scan Findings |
| POST | `/api/v1/organizations/{org_id}/scans/{scan_id}/rescan` | Rescan |

## schedules

| Method | Path | Summary |
|---|---|---|
| GET | `/api/v1/organizations/{org_id}/schedules` | List Schedules |
| POST | `/api/v1/organizations/{org_id}/schedules` | Create Schedule |
| DELETE | `/api/v1/organizations/{org_id}/schedules/{schedule_id}` | Delete Schedule |
| PATCH | `/api/v1/organizations/{org_id}/schedules/{schedule_id}` | Update Schedule |
