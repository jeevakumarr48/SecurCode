/** Typed fetch wrapper for the SecurCode /api/v1 platform.
 *
 * Authentication is an HttpOnly session cookie the browser sends
 * automatically; JavaScript never sees it. The CSRF token is kept only in
 * memory and attached to state-changing requests.
 */

// The platform API is always reached on the console's own origin (Vercel rewrite,
// nginx or the Vite dev proxy) so the session cookie stays first-party and is
// never sent cross-site. VITE_API_BASE_URL only configures the legacy console.
export const API_BASE = "/api/v1";

let csrfToken: string | null = null;
let onUnauthorized: (() => void) | null = null;

export function setCsrfToken(token: string | null) {
  csrfToken = token;
}

export function setUnauthorizedHandler(handler: (() => void) | null) {
  onUnauthorized = handler;
}

export class ApiError extends Error {
  status: number;
  requestId?: string;
  errors?: { loc: string[]; msg: string }[];

  constructor(status: number, message: string, requestId?: string, errors?: { loc: string[]; msg: string }[]) {
    super(message);
    this.status = status;
    this.requestId = requestId;
    this.errors = errors;
  }
}

type Query = Record<string, string | number | boolean | string[] | null | undefined>;

export function buildUrl(path: string, query?: Query) {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query ?? {})) {
    if (value === undefined || value === null || value === "") continue;
    if (Array.isArray(value)) value.forEach((item) => params.append(key, item));
    else params.set(key, String(value));
  }
  const qs = params.toString();
  return `${API_BASE}${path}${qs ? `?${qs}` : ""}`;
}

async function request<T>(method: string, path: string, options: { body?: unknown; query?: Query; form?: FormData; headers?: Record<string, string> } = {}): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json", ...(options.headers ?? {}) };
  if (method !== "GET" && csrfToken) headers["X-CSRF-Token"] = csrfToken;
  let body: BodyInit | undefined;
  if (options.form) body = options.form;
  else if (options.body !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(options.body);
  }
  const response = await fetch(buildUrl(path, options.query), { method, headers, body, credentials: "include" });
  const requestId = response.headers.get("x-request-id") ?? undefined;
  const contentType = response.headers.get("content-type") ?? "";
  const payload = contentType.includes("application/json") ? await response.json().catch(() => null) : await response.text();
  if (!response.ok) {
    if (response.status === 401 && onUnauthorized && !path.startsWith("/auth/login")) onUnauthorized();
    const detail = typeof payload === "object" && payload && "detail" in payload ? String((payload as { detail: unknown }).detail) : `Request failed (${response.status})`;
    const errors = typeof payload === "object" && payload && "errors" in payload ? (payload as { errors: { loc: string[]; msg: string }[] }).errors : undefined;
    throw new ApiError(response.status, detail, requestId, errors);
  }
  return payload as T;
}

export const api = {
  get: <T>(path: string, query?: Query) => request<T>("GET", path, { query }),
  post: <T>(path: string, body?: unknown, headers?: Record<string, string>) => request<T>("POST", path, { body, headers }),
  patch: <T>(path: string, body?: unknown) => request<T>("PATCH", path, { body }),
  put: <T>(path: string, body?: unknown) => request<T>("PUT", path, { body }),
  delete: <T>(path: string, body?: unknown) => request<T>("DELETE", path, { body }),
  upload: <T>(path: string, file: File) => {
    const form = new FormData();
    form.append("file", file);
    return request<T>("POST", path, { form });
  },
};

/** Download an authenticated export by streaming it through a Blob URL. */
export async function download(path: string, query: Query, fallbackName: string) {
  const response = await fetch(buildUrl(path, query), { credentials: "include" });
  if (!response.ok) {
    const text = await response.text();
    let detail = `Export failed (${response.status})`;
    try { detail = JSON.parse(text).detail ?? detail; } catch { /* plain text */ }
    throw new ApiError(response.status, detail);
  }
  const blob = await response.blob();
  const disposition = response.headers.get("content-disposition") ?? "";
  const name = /filename="([^"]+)"/.exec(disposition)?.[1] ?? fallbackName;
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = name;
  anchor.click();
  URL.revokeObjectURL(url);
}

export function errorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    const field = error.errors?.[0];
    return field ? `${error.message} ${field.loc.slice(-1)[0]}: ${field.msg}` : error.message;
  }
  if (error instanceof Error) return error.message;
  return "Something went wrong.";
}
