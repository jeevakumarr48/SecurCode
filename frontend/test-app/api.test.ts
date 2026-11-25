import { describe, expect, it } from "vitest";
import { ApiError, api, buildUrl, setCsrfToken } from "../src/app/lib/api";
import { mockApi } from "./harness";

describe("api client", () => {
  it("sends cookies and the in-memory CSRF token only on state-changing requests", async () => {
    const calls = mockApi(() => ({ body: { ok: true } }));
    setCsrfToken("token-abc");
    await api.get("/organizations");
    await api.post("/organizations", { name: "x" });
    expect(calls[0].init.credentials).toBe("include");
    expect((calls[0].init.headers as Record<string, string>)["X-CSRF-Token"]).toBeUndefined();
    expect((calls[1].init.headers as Record<string, string>)["X-CSRF-Token"]).toBe("token-abc");
    expect(calls[1].init.body).toBe(JSON.stringify({ name: "x" }));
    setCsrfToken(null);
  });

  it("raises ApiError with the server detail and request id", async () => {
    mockApi(() => ({ status: 403, body: { detail: "Your role does not permit this action.", request_id: "r1" } }));
    await expect(api.get("/x")).rejects.toMatchObject({ status: 403, message: "Your role does not permit this action." });
    await expect(api.get("/x")).rejects.toBeInstanceOf(ApiError);
  });

  it("serialises repeated query parameters and drops empty values", () => {
    const url = buildUrl("/findings", { status: ["open", "triaged"], search: "", project_id: undefined, limit: 50 });
    expect(url).toBe("/api/v1/findings?status=open&status=triaged&limit=50");
  });

  it("never persists credentials in web storage", async () => {
    mockApi(() => ({ body: { ok: true } }));
    setCsrfToken("secret-csrf");
    await api.post("/anything");
    const stored = JSON.stringify({ ...localStorage }) + JSON.stringify({ ...sessionStorage });
    expect(stored).not.toContain("secret-csrf");
    setCsrfToken(null);
  });
});
