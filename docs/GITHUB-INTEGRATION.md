# GitHub integration status

## Repository workflow

`.github/workflows/codeql.yml` runs GitHub CodeQL for Python and JavaScript/TypeScript on pushes and pull requests targeting `main`, weekly, and by manual dispatch. It uses CodeQL's `security-extended` query set and uploads SARIF through the official CodeQL action. The existing `security-check.yml` also runs the SecurCode changed-file gate, backend/frontend checks, and Trivy.

The CodeQL workflow needs GitHub Actions enabled and permission to upload security events. Private repositories may require GitHub Advanced Security or an organization policy that enables Code Security. The workflow file is implemented but has not been executed against a GitHub repository from this workspace.

## Importing SARIF into a local SecurCode workspace

The API accepts SARIF 2.x through `POST /integrations/sarif/import` with `{ "project_id": 1, "sarif": { ... }, "branch": "refs/pull/42/merge", "commit_sha": "<hex sha>", "pull_request_number": 42, "source_url": "https://github.com/.../actions/runs/..." }`. The Git metadata fields are optional; commit IDs and HTTPS source URLs are validated and stored on each scan for history and correlation. It normalizes rule ID, severity, CWE tags, message, path, line, and scanner attribution. Absolute and traversal paths are redacted. Payloads above 25 MB are rejected.

This import is an authenticated local API. SecurCode does not connect to GitHub repositories, retrieve workflow artifacts, exchange GitHub credentials, or post custom check-run conclusions. No GitHub token is accepted or stored. The CodeQL action uploads findings to GitHub's own code scanning interface and workflow checks run on PRs; local SARIF import can associate those findings with branch/commit/PR metadata when provided by a trusted caller. Live repository authorization and artifact round-trip require a GitHub App/OIDC integration and credentials.

## Pull-request checks

The SecurCode changed-file gate in `security-check.yml` is configured to fail on High findings. CodeQL SARIF uploads populate GitHub's code scanning interface, subject to repository configuration. Branch protection and required-check policy must be configured by the repository administrator; SecurCode cannot enforce those remote settings from this local repository.

## Local verification status

On 2026-11-06, anonymous access to the configured public GitHub origin was verified with a shallow clone. The retrieved revision `53bdef8bb4bc8beb4172693cef74145789a14645` was scanned locally by the built-in scanner without executing repository code: status `completed`, 0 scan errors, and 4 findings (2 `SEC001`, 2 `SEC002`). No GitHub token was present or used. This confirms public source retrieval and local scanner operation only; it does not exercise the SecurCode UI/API repository URL field, private repository access, a GitHub Actions run, or SARIF artifact round-trip. The product does not fetch remote URLs.

The local SARIF parser and import route are covered by deterministic tests, including a two-user cross-project denial test. GitHub Actions enablement, CodeQL workflow execution, private repository authorization, and live SARIF artifact retrieval remain unverified or unimplemented.

## Multi-tenant platform integration

The sections above describe the legacy single-tenant console. The multi-tenant platform (`/api/v1`) adds a real GitHub connection per organisation.

### Architecture and trade-offs

The platform uses a **fine-grained personal access token per organisation integration**. A GitHub App with per-installation, short-lived tokens is the better long-term design, but it requires registering an App and managing its private key. That is on the roadmap.

| Aspect | Token integration (implemented) | GitHub App (roadmap) |
|---|---|---|
| Token lifetime | Long-lived until revoked or expired in GitHub | 1-hour installation tokens |
| Scope | Whatever the token was granted (recommend fine-grained, selected repositories) | Per-installation, per-permission |
| Identity | Acts as the user who created it | Acts as the App |
| Revocation | SecurCode deletes its copy; the user must also revoke it in GitHub | Uninstall the App |

Recommended fine-grained token permissions: **Repository access:** only the repositories to scan. **Contents: Read** and **Metadata: Read** (required). **Commit statuses: Read & write** and **Pull requests: Read & write** (only if PR summaries should be posted).

### Security properties

- The token is validated against `GET /user`, Fernet-encrypted at rest, and never returned to the browser (UI shows `…last4`).
- Only `SECURCODE_GITHUB_API_URL` (default `https://api.github.com`) and `codeload.github.com` are ever contacted. Redirects are followed manually to those hosts only, and the token is never sent to the archive host.
- Repository names and refs are validated. Refs are resolved to a 40-character commit SHA, and that exact commit is scanned and recorded.
- A `401` or `403` from GitHub marks the integration `error` with a message, so expired and revoked credentials show up in the UI and admin views.
- **Disconnect** deletes the stored token and webhook secret and marks the integration `revoked`.

### Connect and scan

1. **GitHub integration → Connect**: paste the token. The response shows a webhook secret **once**.
2. **Projects → New project → GitHub repository**: choose the integration and `owner/repo` and set the default branch.
3. **Start scan** on any branch. The worker resolves the branch to a commit, downloads the tarball, extracts it safely and scans it. Scope `branch:<name>` keeps each branch's lifecycle separate.

### Webhooks and pull requests

In the repository settings add a webhook:

- Payload URL: `https://<your-web-domain>/api/v1/webhooks/github/<integration-id>` (shown in the UI)
- Content type `application/json`; secret: the value shown at connection time
- Events: **Pull requests** (and **Pushes** if push scanning is enabled)

Processing:

- `X-Hub-Signature-256` HMAC is verified in constant time. Unknown integrations and bad signatures get the same `401`.
- `X-GitHub-Delivery` ids are stored with a unique constraint, so a replayed or redelivered event is acknowledged as `duplicate` and ignored.
- `pull_request` `opened`/`synchronize`/`reopened` events queue a scan of the head commit with scope `pr:<number>` (idempotent per commit).
- When the scan finishes, SecurCode compares it with the latest **complete** default-branch scan and posts:
  - a commit status `securcode/sast`: `success` (informational), or `failure` only when the organisation set **Security policy → Fail pull-request checks at** a severity and a new finding meets it, or `error` if the scan was incomplete;
  - a PR comment listing only **newly introduced** findings that were actually detected.
- `push` to the default branch queues a scan only when "auto scan push" is enabled.

### Verification status

The integration and webhook flows are covered by automated tests against a mocked GitHub API (`backend/tests_v1/test_integrations.py`): connection, repository and branch listing, branch scan from tarball, expired credentials, disconnect, webhook signature, replay, PR summary and threshold failure. **They have not been run against live github.com from this environment**, because no GitHub credentials were available. Verify with a test repository after deployment.
