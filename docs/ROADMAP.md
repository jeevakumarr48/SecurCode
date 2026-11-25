# Known limitations and roadmap

## Known limitations (current release)

**Scanner**
- No cross-file or interprocedural analysis beyond depth-2 direct calls in one Python file. JavaScript/TypeScript rules are lexical (no data flow and no alias tracking). Python, JavaScript and TypeScript only.
- Fingerprints change on file rename or when the flagged line is edited.
- No dependency (SCA), secrets-history, IaC or container scanning in the product itself. These run in CI through Trivy, pip-audit and npm audit.

**Platform**
- Isolation is enforced in the application layer and tested; PostgreSQL row-level security is not enabled.
- The scan sandbox is process-level (isolated interpreter + rlimits), not a per-scan container or microVM.
- GitHub uses fine-grained personal access tokens, not a GitHub App.
- No PDF renderer: reports are printable HTML (browser "Save as PDF").
- AI-assisted remediation is not implemented; guidance is deterministic and rule-based (the UI says so).
- Global platform configuration is read-only in the admin UI and changed through environment variables.
- There is no encryption-key rotation command yet.
- Free hosting tiers sleep, expire databases (Render's free Postgres expires after 30 days) or lack background workers. See the deployment guide.

**Verification**
- The live GitHub, SMTP, container build and public deployment paths are not verified from the development environment. CI covers container builds.
- No load testing or independent penetration test.

## Roadmap

1. **GitHub App** with installation tokens and check runs (replacing personal access tokens).
2. **PostgreSQL row-level security** as a second isolation layer, keyed on a per-request `app.org_id` setting.
3. **Per-scan container sandbox** (gVisor or Firecracker) with no network egress.
4. **Parser-based JS/TS analysis** (TypeScript compiler API or tree-sitter) with intra-file data flow.
5. **Interprocedural Python taint** across modules, plus a framework model library (Django, FastAPI, SQLAlchemy).
6. **Server-side PDF** report rendering and scheduled report delivery.
7. **`MultiFernet` key rotation** CLI and audit-chain anchoring to external storage.
8. **Optional AI explanations**, opt-in per organisation, clearly labelled as generated advice, never sent without consent.
9. **SSO** (OIDC/SAML) and SCIM for enterprise organisations.
10. **Larger benchmark**, using public vulnerable-app corpora (OWASP Benchmark for Python, NodeGoat) to measure precision and recall on realistic code.
