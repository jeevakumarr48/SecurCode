import { useState } from "react";
import { useNavigate } from "react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, errorMessage } from "../lib/api";
import { useAuth } from "../lib/auth";
import { ROLE_LABELS, dateTime, humanize, timeAgo } from "../lib/format";
import type { Notification, SessionPayload } from "../lib/types";
import { Button, Checkbox, EmptyState, ErrorState, Mono, Notice, PageHeader, Section, Skeleton, StatusBadge, Table, TextInput } from "../components/ui";

export function ProfilePage() {
  const { session, setSession } = useAuth();
  const [name, setName] = useState(session?.user.display_name ?? "");
  const save = useMutation({ mutationFn: () => api.patch<SessionPayload>("/auth/me", { display_name: name }), onSuccess: setSession });
  if (!session) return null;
  return (
    <div className="max-w-2xl">
      <PageHeader title="Profile" description={`${session.user.email}${session.user.email_verified ? " · verified" : " · not verified"}`} />
      <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); save.mutate(); }}>
        <TextInput label="Display name" value={name} onChange={(e) => setName(e.target.value)} />
        {save.isSuccess && <Notice tone="ok">Saved.</Notice>}
        {save.error && <Notice tone="error">{errorMessage(save.error)}</Notice>}
        <Button type="submit" variant="primary" busy={save.isPending}>Save</Button>
      </form>
      <Section title="Organizations" className="mt-10">
        <Table head={["Organization", "Role", "Status"]}>
          {session.organizations.map((org) => <tr key={org.id}><td>{org.name}</td><td>{ROLE_LABELS[org.role]}</td><td><StatusBadge status={org.status} /></td></tr>)}
        </Table>
      </Section>
    </div>
  );
}

interface SessionRow { id: string; created_at: string; last_seen_at: string; expires_at: string; ip_address: string | null; user_agent: string | null; current: boolean }

export function AccountSecurityPage() {
  const { session, refresh, setSession } = useAuth();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [passwords, setPasswords] = useState({ current_password: "", new_password: "" });
  const [mfaSetup, setMfaSetup] = useState<{ secret: string; otpauth_uri: string } | null>(null);
  const [code, setCode] = useState("");
  const [disable, setDisable] = useState({ password: "", code: "" });
  const [message, setMessage] = useState<{ tone: "ok" | "error"; text: string } | null>(null);
  const sessions = useQuery({ queryKey: ["sessions"], queryFn: () => api.get<{ items: SessionRow[] }>("/auth/sessions") });
  const reloadSessions = () => queryClient.invalidateQueries({ queryKey: ["sessions"] });
  const onError = (err: unknown) => setMessage({ tone: "error", text: errorMessage(err) });
  const change = useMutation({
    mutationFn: () => api.post<{ other_sessions_revoked: number }>("/auth/password/change", passwords),
    onSuccess: (r) => { setPasswords({ current_password: "", new_password: "" }); setMessage({ tone: "ok", text: `Password changed. ${r.other_sessions_revoked} other session(s) signed out.` }); void reloadSessions(); },
    onError,
  });
  const revoke = useMutation({
    mutationFn: (row: SessionRow) => api.delete(`/auth/sessions/${row.id}`),
    onSuccess: async (_, row) => { if (row.current) { setSession(null); navigate("/login"); } else void reloadSessions(); },
    onError,
  });
  const revokeOthers = useMutation({ mutationFn: () => api.post<{ count: number }>("/auth/sessions/revoke-others"), onSuccess: (r) => { setMessage({ tone: "ok", text: `${r.count} session(s) revoked.` }); void reloadSessions(); }, onError });
  const startMfa = useMutation({ mutationFn: () => api.post<{ secret: string; otpauth_uri: string }>("/auth/mfa/setup"), onSuccess: setMfaSetup, onError });
  const enableMfa = useMutation({ mutationFn: () => api.post("/auth/mfa/enable", { code }), onSuccess: async () => { setMfaSetup(null); setCode(""); setMessage({ tone: "ok", text: "Two-factor authentication enabled." }); const s = await refresh(); if (s) setSession(s); }, onError });
  const disableMfa = useMutation({ mutationFn: () => api.post("/auth/mfa/disable", disable), onSuccess: async () => { setDisable({ password: "", code: "" }); setMessage({ tone: "ok", text: "Two-factor authentication disabled." }); const s = await refresh(); if (s) setSession(s); }, onError });
  if (!session) return null;
  return (
    <div className="max-w-3xl">
      <PageHeader title="Account security" description="Manage your password, two-factor authentication and active sessions." />
      {message && <div className="mb-4"><Notice tone={message.tone}>{message.text}</Notice></div>}
      <Section title="Password">
        <form className="grid max-w-xl gap-3 sm:grid-cols-2" onSubmit={(e) => { e.preventDefault(); change.mutate(); }}>
          <TextInput label="Current password" type="password" autoComplete="current-password" value={passwords.current_password} onChange={(e) => setPasswords({ ...passwords, current_password: e.target.value })} required />
          <TextInput label="New password" type="password" autoComplete="new-password" minLength={12} value={passwords.new_password} onChange={(e) => setPasswords({ ...passwords, new_password: e.target.value })} required />
          <div><Button type="submit" variant="primary" busy={change.isPending}>Change password</Button></div>
        </form>
      </Section>
      <Section title="Two-factor authentication (TOTP)" className="mt-8">
        {session.user.mfa_enabled ? (
          <form className="flex flex-wrap items-end gap-3" onSubmit={(e) => { e.preventDefault(); disableMfa.mutate(); }}>
            <p className="w-full text-[13px] text-ok">Enabled. Sign-in requires a code from your authenticator app.</p>
            <div className="w-56"><TextInput label="Password" type="password" value={disable.password} onChange={(e) => setDisable({ ...disable, password: e.target.value })} /></div>
            <div className="w-40"><TextInput label="Current code" inputMode="numeric" maxLength={6} value={disable.code} onChange={(e) => setDisable({ ...disable, code: e.target.value })} /></div>
            <Button type="submit" variant="danger" busy={disableMfa.isPending}>Disable</Button>
          </form>
        ) : mfaSetup ? (
          <div className="space-y-3 text-[13px]">
            <p>Add this key to your authenticator app (it is shown only once), then enter the 6-digit code it shows.</p>
            <div>Setup key: <Mono className="select-all break-all text-fg">{mfaSetup.secret}</Mono></div>
            <div className="text-xs text-faint">Or use the URI: <Mono className="break-all">{mfaSetup.otpauth_uri}</Mono></div>
            <form className="flex items-end gap-3" onSubmit={(e) => { e.preventDefault(); enableMfa.mutate(); }}>
              <div className="w-40"><TextInput label="Code" inputMode="numeric" maxLength={6} value={code} onChange={(e) => setCode(e.target.value)} /></div>
              <Button type="submit" variant="primary" busy={enableMfa.isPending}>Verify &amp; enable</Button>
            </form>
          </div>
        ) : <Button onClick={() => startMfa.mutate()} busy={startMfa.isPending}>Set up two-factor authentication</Button>}
      </Section>
      <Section title="Active sessions" className="mt-8" actions={<Button variant="ghost" onClick={() => revokeOthers.mutate()}>Sign out other sessions</Button>}>
        {sessions.isLoading ? <Skeleton /> : (
          <Table head={["Device", "IP address", "Signed in", "Last active", ""]}>
            {sessions.data?.items.map((row) => (
              <tr key={row.id}>
                <td className="max-w-xs truncate" title={row.user_agent ?? ""}>{row.user_agent?.slice(0, 60) || "Unknown"}{row.current && <span className="ml-2 text-xs text-ok">this session</span>}</td>
                <td><Mono>{row.ip_address}</Mono></td><td className="text-muted">{dateTime(row.created_at)}</td><td className="text-muted">{timeAgo(row.last_seen_at)}</td>
                <td className="text-right"><Button variant="ghost" onClick={() => revoke.mutate(row)}>{row.current ? "Sign out" : "Revoke"}</Button></td>
              </tr>
            ))}
          </Table>
        )}
      </Section>
    </div>
  );
}

export function NotificationsPage() {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [unreadOnly, setUnreadOnly] = useState(false);
  const { data, isLoading, error } = useQuery({ queryKey: ["notifications", unreadOnly], queryFn: () => api.get<{ unread: number; items: Notification[] }>("/notifications", { unread_only: unreadOnly, limit: 100 }) });
  const prefs = useQuery({ queryKey: ["notification-prefs"], queryFn: () => api.get<{ email_available: boolean; items: { kind: string; in_app: boolean; email: boolean }[] }>("/notifications/preferences") });
  const invalidate = () => queryClient.invalidateQueries({ queryKey: ["notifications"] });
  const read = useMutation({ mutationFn: (id: string) => api.post(`/notifications/${id}/read`), onSuccess: invalidate });
  const readAll = useMutation({ mutationFn: () => api.post("/notifications/read-all"), onSuccess: invalidate });
  const setPref = useMutation({ mutationFn: (body: { kind: string; in_app: boolean; email: boolean }) => api.put("/notifications/preferences", body), onSuccess: () => queryClient.invalidateQueries({ queryKey: ["notification-prefs"] }) });
  return (
    <>
      <PageHeader title="Notifications" description={data ? `${data.unread} unread` : undefined} actions={<Button onClick={() => readAll.mutate()}>Mark all read</Button>} />
      <div className="mb-4"><Checkbox label="Unread only" checked={unreadOnly} onChange={setUnreadOnly} /></div>
      {isLoading && <Skeleton />}
      {error && <ErrorState error={error} />}
      {data && (data.items.length === 0 ? <EmptyState title="You're all caught up" /> : (
        <ul className="divide-y divide-line-soft border border-line">
          {data.items.map((n) => (
            <li key={n.id} className={n.read ? "px-4 py-3" : "border-l-2 border-accent bg-accent-soft/20 px-4 py-3"}>
              <button type="button" className="w-full text-left" onClick={() => { if (!n.read) read.mutate(n.id); if (n.link?.startsWith("/")) navigate(n.link); }}>
                <div className="flex justify-between gap-3"><span className="text-[13px] font-medium text-fg">{n.title}</span><span className="whitespace-nowrap text-xs text-faint">{timeAgo(n.created_at)}</span></div>
                {n.body && <p className="text-[13px] text-muted">{n.body}</p>}
              </button>
            </li>
          ))}
        </ul>
      ))}
      <Section title="Preferences" className="mt-10">
        {!prefs.data?.email_available && <p className="mb-3 text-xs text-faint">Email delivery is not configured on this instance, so only in-app notifications are delivered.</p>}
        <Table head={["Notification", "In-app", "Email"]}>
          {prefs.data?.items.map((p) => (
            <tr key={p.kind}><td>{humanize(p.kind)}</td>
              <td><Checkbox label="" checked={p.in_app} onChange={(v) => setPref.mutate({ ...p, in_app: v })} /></td>
              <td><Checkbox label="" checked={p.email} disabled={!prefs.data?.email_available} onChange={(v) => setPref.mutate({ ...p, email: v })} /></td></tr>
          ))}
        </Table>
      </Section>
    </>
  );
}

interface AdminOverview { organizations: Record<string, number>; users: Record<string, number>; scans: Record<string, number>; scans_last_24h: number; failed_last_24h: number; workers_active: number; integrations: Record<string, number>; audit_chain: { valid: boolean; checked: number }; scanner_version: string; ruleset_version: string }

export function AdminPage() {
  const queryClient = useQueryClient();
  const [reason, setReason] = useState("");
  const overview = useQuery({ queryKey: ["admin", "overview"], queryFn: () => api.get<AdminOverview>("/admin/overview") });
  const orgs = useQuery({ queryKey: ["admin", "orgs"], queryFn: () => api.get<{ items: { id: string; name: string; status: string; members: number; projects: number; is_demo: boolean; created_at: string }[] }>("/admin/organizations") });
  const users = useQuery({ queryKey: ["admin", "users"], queryFn: () => api.get<{ items: { id: string; email: string; is_active: boolean; is_platform_admin: boolean; mfa_enabled: boolean; locked: boolean; organizations: number; last_login_at: string | null }[] }>("/admin/users") });
  const jobs = useQuery({ queryKey: ["admin", "jobs"], queryFn: () => api.get<{ queue: Record<string, number>; stale_leases: number; workers: { worker_id: string; healthy: boolean; active_jobs: number; last_seen_at: string; version: string }[]; recent_failures: { scan_id: string; error: string; finished_at: string }[] }>("/admin/jobs") });
  const events = useQuery({ queryKey: ["admin", "events"], queryFn: () => api.get<{ items: { id: number; action: string; actor_email: string | null; ip_address: string | null; created_at: string }[] }>("/admin/security-events", { limit: 50 }) });
  const config = useQuery({ queryKey: ["admin", "config"], queryFn: () => api.get<Record<string, string | number | boolean>>("/admin/config") });
  const act = useMutation({ mutationFn: (path: string) => api.post(path, { reason }), onSuccess: () => queryClient.invalidateQueries({ queryKey: ["admin"] }) });
  if (overview.error) return <ErrorState error={overview.error} />;
  return (
    <>
      <PageHeader title="Platform administration" description="Aggregate operational data. Platform administrators have no access to tenant source code or finding details unless they are also members of that organization. Every view here is audited." />
      {overview.data && (
        <div className="mb-8 grid grid-cols-2 gap-6 md:grid-cols-6">
          {[["Organizations", overview.data.organizations.total], ["Users", overview.data.users.total], ["Locked users", overview.data.users.locked],
            ["Scans (24h)", overview.data.scans_last_24h], ["Failed (24h)", overview.data.failed_last_24h], ["Active workers", overview.data.workers_active]].map(([label, value]) => (
            <div key={String(label)} className="border-l border-line pl-3"><div className="text-xs text-muted">{label}</div><div className="tabular text-2xl font-semibold">{value}</div></div>
          ))}
        </div>
      )}
      {overview.data && <div className="mb-6"><Notice tone={overview.data.audit_chain.valid ? "ok" : "error"}>Audit chain {overview.data.audit_chain.valid ? "verified" : "BROKEN"} ({overview.data.audit_chain.checked} events). Scanner {overview.data.scanner_version}, rule set {overview.data.ruleset_version}.</Notice></div>}
      <div className="mb-4 w-96"><TextInput label="Reason for administrative actions (required, audited)" value={reason} onChange={(e) => setReason(e.target.value)} /></div>
      {act.error && <div className="mb-3"><Notice tone="error">{errorMessage(act.error)}</Notice></div>}
      <Section title="Organizations">
        <Table head={["Organization", "Members", "Projects", "Status", ""]}>
          {orgs.data?.items.map((o) => <tr key={o.id}><td>{o.name}{o.is_demo && <span className="ml-2 text-xs text-faint">demo</span>}</td><td className="tabular">{o.members}</td><td className="tabular">{o.projects}</td><td><StatusBadge status={o.status} /></td>
            <td className="text-right"><Button variant="ghost" disabled={reason.length < 5} onClick={() => act.mutate(`/admin/organizations/${o.id}/${o.status === "suspended" ? "reactivate" : "suspend"}`)}>{o.status === "suspended" ? "Reactivate" : "Suspend"}</Button></td></tr>)}
        </Table>
      </Section>
      <Section title="Users" className="mt-8">
        <Table head={["User", "Orgs", "MFA", "Last login", "State", ""]}>
          {users.data?.items.map((u) => <tr key={u.id}><td>{u.email}{u.is_platform_admin && <span className="ml-2 text-xs text-accent">platform admin</span>}</td><td className="tabular">{u.organizations}</td><td>{u.mfa_enabled ? "On" : "Off"}</td><td className="text-muted">{timeAgo(u.last_login_at)}</td>
            <td>{u.is_active ? (u.locked ? <StatusBadge status="pending" /> : <StatusBadge status="active" />) : <StatusBadge status="revoked" />}</td>
            <td className="text-right"><Button variant="ghost" disabled={reason.length < 5} onClick={() => act.mutate(`/admin/users/${u.id}/${u.is_active ? "disable" : "enable"}`)}>{u.is_active ? "Disable" : "Enable"}</Button></td></tr>)}
        </Table>
      </Section>
      <div className="mt-8 grid gap-8 lg:grid-cols-2">
        <Section title="Background jobs">
          {jobs.data && <div className="space-y-3 text-[13px]">
            <p>Queued {jobs.data.queue.queued ?? 0} · running {jobs.data.queue.running ?? 0} · stale leases {jobs.data.stale_leases}</p>
            <ul>{jobs.data.workers.map((w) => <li key={w.worker_id}><StatusBadge status={w.healthy ? "active" : "error"} /> <Mono>{w.worker_id}</Mono> · {w.active_jobs} active · seen {timeAgo(w.last_seen_at)}</li>)}</ul>
            {jobs.data.workers.length === 0 && <Notice tone="warning">No worker has reported in. Scans stay queued until a worker runs.</Notice>}
            <div className="text-xs text-muted">Recent failures</div>
            <ul className="text-xs">{jobs.data.recent_failures.map((f) => <li key={f.scan_id}><Mono>{f.scan_id.slice(0, 8)}</Mono> {f.error}</li>)}</ul>
          </div>}
        </Section>
        <Section title="Platform security events">
          <ul className="max-h-80 space-y-1 overflow-auto text-[12px]">{events.data?.items.map((e) => <li key={e.id}><span className="text-faint">{dateTime(e.created_at)}</span> <Mono>{e.action}</Mono> {e.actor_email ?? "anonymous"} <span className="text-faint">{e.ip_address}</span></li>)}</ul>
        </Section>
      </div>
      <Section title="Effective configuration (read-only; set through environment variables)" className="mt-8">
        <dl className="grid gap-x-6 gap-y-1 text-[13px] sm:grid-cols-2">{Object.entries(config.data ?? {}).map(([k, v]) => <div key={k} className="flex justify-between border-b border-line-soft py-1"><dt className="text-muted">{k}</dt><dd><Mono>{String(v)}</Mono></dd></div>)}</dl>
      </Section>
    </>
  );
}
