import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ORG_ID, mockApi, renderApp, session } from "./harness";

const emptyDashboard = {
  generated_at: "", is_demo: false, window_days: 30,
  totals: { projects: 0, scans: 0, active_findings: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, new_findings: 0, resolved_findings: 0, recurring_findings: 0, open_remediation_tasks: 0, overdue: 0 },
  scan_health: { success_rate: null, average_duration_ms: null, running: 0, queued: 0, failed: 0 },
  status_breakdown: {}, remediation_progress: { remediated: 0, total: 0, ratio: null },
  posture: { score: null, grade: null, formula: "posture-v1", projects: [] }, trend: [], distribution: { cwe: [], owasp: [], language: [] },
};

function baseHandler(role: Parameters<typeof session>[0] = "owner") {
  return (url: URL) => {
    if (url.pathname === "/api/v1/auth/session") return { body: session(role) };
    if (url.pathname === "/api/v1/notifications") return { body: { unread: 2, items: [] } };
    if (url.pathname.endsWith("/analytics/dashboard")) return { body: emptyDashboard };
    if (url.pathname.endsWith("/scans")) return { body: { items: [], total: 0, limit: 6, offset: 0 } };
    return undefined;
  };
}

describe("application", () => {
  it("redirects unauthenticated users to sign-in with a return path", async () => {
    mockApi((url) => (url.pathname === "/api/v1/auth/session" ? { status: 401, body: { detail: "Authentication required." } } : undefined));
    renderApp(`/orgs/${ORG_ID}/findings`);
    expect(await screen.findByRole("heading", { name: "Sign in to SecurCode" })).toBeInTheDocument();
  });

  it("signs in, completes the MFA challenge with the pending CSRF token, and lands on the dashboard", async () => {
    let signedIn = false;
    const calls = mockApi((url, init) => {
      if (url.pathname === "/api/v1/auth/session") return signedIn ? { body: session() } : { status: 401, body: { detail: "Authentication required." } };
      if (url.pathname === "/api/v1/auth/login") return { body: { status: "mfa_required", csrf_token: "pending-csrf" } };
      if (url.pathname === "/api/v1/auth/mfa/verify") {
        expect((init.headers as Record<string, string>)["X-CSRF-Token"]).toBe("pending-csrf");
        signedIn = true;
        return { body: { status: "authenticated", ...session() } };
      }
      return baseHandler()(url);
    });
    const user = userEvent.setup();
    renderApp("/login");
    await user.type(await screen.findByLabelText("Email"), "owner@example.com");
    await user.type(screen.getByLabelText("Password"), "Correct-Horse-Battery-42");
    await user.click(screen.getByRole("button", { name: "Sign in" }));
    await user.type(await screen.findByLabelText(/6-digit code/), "123456");
    await user.click(screen.getByRole("button", { name: "Verify" }));
    expect(await screen.findByRole("heading", { name: "Security overview" })).toBeInTheDocument();
    expect(calls.some((c) => c.url.pathname === "/api/v1/auth/mfa/verify")).toBe(true);
    expect(await screen.findByText("No projects yet")).toBeInTheDocument();
  });

  it("shows only metrics from the API and an empty state when there is no data", async () => {
    mockApi(baseHandler());
    renderApp(`/orgs/${ORG_ID}/dashboard`);
    expect(await screen.findByText("No projects yet")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Create your first project" })).toBeInTheDocument();
  });

  it("hides governance navigation the role cannot use (backend still enforces it)", async () => {
    mockApi(baseHandler("developer"));
    renderApp(`/orgs/${ORG_ID}/dashboard`);
    const nav = await screen.findByRole("navigation", { name: "Organization navigation" });
    expect(within(nav).getByRole("link", { name: "My remediation" })).toBeInTheDocument();
    expect(within(nav).queryByRole("link", { name: "Audit log" })).not.toBeInTheDocument();
    expect(within(nav).queryByRole("link", { name: "GitHub integration" })).not.toBeInTheDocument();
  });

  it("refuses to render an organization the user is not a member of", async () => {
    mockApi(baseHandler());
    renderApp(`/orgs/${"b".repeat(32)}/dashboard`);
    expect(await screen.findByRole("heading", { name: "Organization not found" })).toBeInTheDocument();
  });

  it("shows unread notification count in the top bar", async () => {
    mockApi(baseHandler());
    renderApp(`/orgs/${ORG_ID}/dashboard`);
    expect(await screen.findByRole("link", { name: "Notifications, 2 unread" })).toBeInTheDocument();
  });

  it("finding detail offers only the transitions the API allows and requires justification for reviewed statuses", async () => {
    const finding = {
      id: "f1", org_id: ORG_ID, project_id: "p1", project_name: "Shop", scope: "default", rule_id: "PYSEC007", title: "Tainted SQL execution",
      description: "", severity: "critical", original_severity: "critical", confidence: "high", language: "Python", cwe: "CWE-89", owasp: "A03:2021 Injection",
      file_path: "app/server.py", line: 15, status: "open", verification_status: "unverified", assignee: null, assignee_id: null, due_date: null, overdue: false,
      labels: [], first_detected_at: "2026-11-20T00:00:00Z", last_detected_at: "2026-11-20T00:00:00Z", first_scan_id: "s1", last_scan_id: "s1", fixed_scan_id: null,
      recurrence_count: 0, fingerprint: "abc", snippet: "   15 | cursor.execute(f\"...\")", remediation_notes: null,
      guidance: { meaning: "Request-derived data reaches SQL.", recommended_fix: "Bind values as parameters.", validation_steps: ["Rescan"], references: [] },
      ai_assistance: { available: false, reason: "No AI provider is configured." }, events: [], reviews: [],
      allowed_transitions: ["triaged", "in_progress", "fixed", "accepted_risk", "false_positive"],
    };
    let patched: unknown = null;
    mockApi((url, init) => {
      if (url.pathname === `/api/v1/organizations/${ORG_ID}/findings/f1` && init.method === "PATCH") { patched = JSON.parse(String(init.body)); return { body: { changed: ["status"] } }; }
      if (url.pathname === `/api/v1/organizations/${ORG_ID}/findings/f1`) return { body: finding };
      if (url.pathname.endsWith("/members")) return { body: { items: [] } };
      return baseHandler()(url);
    });
    const user = userEvent.setup();
    renderApp(`/orgs/${ORG_ID}/findings/f1`);
    expect(await screen.findByRole("heading", { name: "Tainted SQL execution" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Resolved" })).not.toBeInTheDocument();
    const accept = screen.getByRole("button", { name: "Accepted risk" });
    expect(accept).toBeDisabled();
    await user.type(screen.getByLabelText(/Justification \(accepted risk/), "Compensating control in place until Q3 release.");
    expect(accept).toBeEnabled();
    await user.click(screen.getByRole("button", { name: "Triaged" }));
    await waitFor(() => expect(patched).toEqual({ status: "triaged" }));
  });
});
