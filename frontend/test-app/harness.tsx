import type { ReactNode } from "react";
import { render } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { vi } from "vitest";
import { AuthProvider } from "../src/app/lib/auth";
import App from "../src/app/App";
import type { Role, SessionPayload } from "../src/app/lib/types";

export const ORG_ID = "a".repeat(32);

const PERMISSIONS: Record<Role, string[]> = {
  owner: ["org.view", "org.update", "org.archive", "members.view", "members.manage", "members.manage_privileged", "projects.view_all", "projects.create", "projects.manage", "projects.delete", "scans.run", "scans.cancel", "findings.view", "findings.triage", "findings.remediate", "findings.comment", "findings.severity", "reviews.request", "reviews.approve", "policies.view", "policies.manage", "integrations.view", "integrations.manage", "reports.view", "reports.export", "audit.view", "schedules.manage"],
  admin: [], security_admin: [], security_analyst: [],
  developer: ["org.view", "members.view", "findings.view", "findings.remediate", "findings.comment", "reports.view", "policies.view"],
  viewer: ["org.view", "members.view", "findings.view", "reports.view", "policies.view"],
};

export function session(role: Role = "owner", overrides: Partial<SessionPayload["user"]> = {}): SessionPayload {
  return {
    user: { id: "u1", email: "owner@example.com", display_name: "Owner", email_verified: true, mfa_enabled: false, is_platform_admin: false, created_at: "2026-11-01T00:00:00Z", ...overrides },
    organizations: [{ id: ORG_ID, name: "Alpha Security", slug: "alpha", status: "active", role, is_demo: false, permissions: PERMISSIONS[role] }],
    active_org_id: ORG_ID,
    csrf_token: "csrf-token-123",
  };
}

type Handler = (url: URL, init: RequestInit) => { status?: number; body: unknown } | undefined;

export function mockApi(handler: Handler) {
  const calls: { url: URL; init: RequestInit }[] = [];
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const url = new URL(String(input), "http://localhost");
    calls.push({ url, init });
    const result = handler(url, init) ?? { status: 404, body: { detail: "Not mocked" } };
    return new Response(JSON.stringify(result.body), { status: result.status ?? 200, headers: { "content-type": "application/json" } });
  });
  vi.stubGlobal("fetch", fetchMock);
  return calls;
}

export function renderApp(path: string, wrapper?: (node: ReactNode) => ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const tree = (
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <AuthProvider><App /></AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>
  );
  return render(<>{wrapper ? wrapper(tree) : tree}</>);
}
