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
