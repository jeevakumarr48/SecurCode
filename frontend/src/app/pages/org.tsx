import { useState } from "react";
import { Link, useNavigate } from "react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { API_BASE, api, download, errorMessage } from "../lib/api";
import { useAuth, useOrg } from "../lib/auth";
import { ROLE_LABELS, dateTime, humanize, timeAgo } from "../lib/format";
import type { AuditEvent, Integration, Invitation, Member, Page, Policy, PolicyConfig, Project, Role, Rule, Schedule } from "../lib/types";
import {
  Button, Checkbox, ConfirmDialog, EmptyState, ErrorState, Mono, Notice, PageHeader, Pagination, Section, Select, SeverityBadge,
  Skeleton, StatusBadge, Table, TextArea, TextInput,
} from "../components/ui";

const ROLES: Role[] = ["owner", "admin", "security_admin", "security_analyst", "developer", "viewer"];

export function TeamPage() {
  const org = useOrg();
  const { session, refresh } = useAuth();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [invite, setInvite] = useState({ email: "", role: "developer" });
  const [link, setLink] = useState<string | null>(null);
  const [message, setMessage] = useState<{ tone: "ok" | "error"; text: string } | null>(null);
  const members = useQuery({ queryKey: ["members", org.id], queryFn: () => api.get<{ items: Member[] }>(`/organizations/${org.id}/members`) });
  const invitations = useQuery({ queryKey: ["invitations", org.id], queryFn: () => api.get<{ items: Invitation[] }>(`/organizations/${org.id}/invitations`), enabled: org.can("members.manage") });
  const activity = useQuery({ queryKey: ["team-activity", org.id], queryFn: () => api.get<{ items: { action: string; actor_email: string; created_at: string }[] }>(`/organizations/${org.id}/activity`, { limit: 15 }) });
  const invalidate = () => { void queryClient.invalidateQueries({ queryKey: ["members", org.id] }); void queryClient.invalidateQueries({ queryKey: ["invitations", org.id] }); };
  const onError = (err: unknown) => setMessage({ tone: "error", text: errorMessage(err) });
  const send = useMutation({
    mutationFn: () => api.post<Invitation>(`/organizations/${org.id}/invitations`, invite),
    onSuccess: (inv) => { setInvite({ email: "", role: invite.role }); setLink(inv.accept_link ?? null); setMessage({ tone: "ok", text: inv.delivery === "smtp" ? `Invitation emailed to ${inv.email}.` : `Invitation created for ${inv.email}.` }); invalidate(); },
    onError,
  });
  const resend = useMutation({ mutationFn: (id: string) => api.post<Invitation>(`/organizations/${org.id}/invitations/${id}/resend`), onSuccess: (inv) => { setLink(inv.accept_link ?? null); invalidate(); }, onError });
  const revoke = useMutation({ mutationFn: (id: string) => api.delete(`/organizations/${org.id}/invitations/${id}`), onSuccess: invalidate, onError });
  const changeRole = useMutation({ mutationFn: ({ id, role }: { id: string; role: string }) => api.patch(`/organizations/${org.id}/members/${id}`, { role }), onSuccess: invalidate, onError });
  const remove = useMutation({
    mutationFn: (id: string) => api.delete(`/organizations/${org.id}/members/${id}`),
    onSuccess: async (_, id) => { if (id === session?.user.id) { await refresh(); navigate("/onboarding"); } else invalidate(); },
    onError,
  });
  const assignable = ROLES.filter((r) => org.can("members.manage_privileged") || !["owner", "admin"].includes(r));
  return (
    <>
      <PageHeader title="Team & invitations" description="Roles apply across this organization and are enforced by the API on every request." />
      {message && <div className="mb-4"><Notice tone={message.tone}>{message.text}</Notice></div>}
      {link && <div className="mb-4"><Notice tone="warning">No email provider is configured, so share this single-use link with the invitee yourself. It is shown only now and expires in 7 days: <Mono className="break-all">{link}</Mono></Notice></div>}
      {org.can("members.manage") && (
        <form className="mb-8 flex flex-wrap items-end gap-3" onSubmit={(e) => { e.preventDefault(); setLink(null); send.mutate(); }}>
          <div className="w-72"><TextInput label="Invite by email" type="email" value={invite.email} onChange={(e) => setInvite({ ...invite, email: e.target.value })} required /></div>
          <div className="w-56"><Select label="Role" value={invite.role} onChange={(e) => setInvite({ ...invite, role: e.target.value })} options={assignable.map((r) => ({ value: r, label: ROLE_LABELS[r] }))} /></div>
          <Button type="submit" variant="primary" busy={send.isPending}>Send invitation</Button>
        </form>
      )}
      <Section title={`Members (${members.data?.items.length ?? 0})`}>
        {members.isLoading ? <Skeleton /> : (
          <Table head={["Member", "Role", "Joined", ""]}>
            {members.data?.items.map((member) => {
              const canEdit = org.can("members.manage") && (org.can("members.manage_privileged") || !["owner", "admin"].includes(member.role));
              return (
                <tr key={member.user_id}>
                  <td>{member.display_name}<div className="text-xs text-faint">{member.email}</div></td>
                  <td className="w-60">{canEdit && member.user_id !== session?.user.id ? (
                    <select aria-label={`Role for ${member.email}`} className="rounded-[3px] border border-line bg-inset px-2 py-1 text-[13px]" value={member.role} onChange={(e) => changeRole.mutate({ id: member.user_id, role: e.target.value })}>
                      {assignable.map((r) => <option key={r} value={r}>{ROLE_LABELS[r]}</option>)}
                    </select>) : ROLE_LABELS[member.role]}</td>
                  <td className="text-muted">{timeAgo(member.joined_at)}</td>
                  <td className="text-right">{(canEdit || member.user_id === session?.user.id) && <Button variant="ghost" onClick={() => remove.mutate(member.user_id)}>{member.user_id === session?.user.id ? "Leave" : "Remove"}</Button>}</td>
                </tr>
              );
            })}
          </Table>
        )}
      </Section>
      {org.can("members.manage") && (
        <Section title="Invitations" className="mt-8">
          {invitations.data?.items.length ? (
            <Table head={["Email", "Role", "State", "Expires", ""]}>
              {invitations.data.items.map((inv) => (
                <tr key={inv.id}>
                  <td>{inv.email}</td><td>{ROLE_LABELS[inv.role]}</td><td><StatusBadge status={inv.state} /></td><td className="text-muted">{dateTime(inv.expires_at)}</td>
                  <td className="text-right">{inv.state === "pending" && <><Button variant="ghost" onClick={() => resend.mutate(inv.id)}>Resend</Button><Button variant="ghost" onClick={() => revoke.mutate(inv.id)}>Revoke</Button></>}</td>
                </tr>
              ))}
            </Table>
          ) : <p className="text-[13px] text-muted">No invitations yet.</p>}
        </Section>
      )}
      <Section title="Recent team activity" className="mt-8">
        <ul className="space-y-1 text-[13px]">{activity.data?.items.map((a, i) => <li key={i}><span className="text-faint">{timeAgo(a.created_at)}</span> · {a.actor_email ?? "SecurCode"} <Mono>{a.action}</Mono></li>)}</ul>
      </Section>
      <RoleMatrix />
    </>
  );
}

function RoleMatrix() {
  const { data } = useQuery({ queryKey: ["matrix"], queryFn: () => api.get<{ roles: Role[]; matrix: Record<Role, string[]> }>("/permissions/matrix") });
  if (!data) return null;
  const permissions = [...new Set(Object.values(data.matrix).flat())].sort();
  return (
    <details className="mt-8">
      <summary className="cursor-pointer text-[13px] text-muted">Role and permission matrix</summary>
      <div className="mt-3"><Table head={["Permission", ...data.roles.map((r) => ROLE_LABELS[r])]}>
        {permissions.map((p) => <tr key={p}><td><Mono>{p}</Mono></td>{data.roles.map((r) => <td key={r} className="text-center">{data.matrix[r].includes(p) ? "✓" : ""}</td>)}</tr>)}
      </Table></div>
    </details>
  );
}

export function OrgSettingsPage() {
  const org = useOrg();
  const { refresh, setSession } = useAuth();
  const [name, setName] = useState(org.name);
  const [timezone, setTimezone] = useState("");
  const [archiving, setArchiving] = useState(false);
  const details = useQuery({ queryKey: ["org", org.id], queryFn: () => api.get<{ settings: Record<string, string>; member_count: number; created_at: string }>(`/organizations/${org.id}`) });
  const save = useMutation({
    mutationFn: () => api.patch(`/organizations/${org.id}`, { name, settings: timezone ? { timezone } : undefined }),
    onSuccess: async () => { const s = await refresh(); if (s) setSession(s); },
  });
  const archive = useMutation({ mutationFn: () => api.post(`/organizations/${org.id}/${org.status === "archived" ? "restore" : "archive"}`), onSuccess: async () => { setArchiving(false); const s = await refresh(); if (s) setSession(s); } });
  return (
    <div className="max-w-2xl">
      <PageHeader title="Organization settings" description={details.data ? `${details.data.member_count} members · created ${dateTime(details.data.created_at)}` : undefined} />
      {org.status === "archived" && <div className="mb-4"><Notice tone="warning">This organization is archived and read-only.</Notice></div>}
      {org.can("org.update") ? (
        <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); save.mutate(); }}>
          <TextInput label="Organization name" value={name} onChange={(e) => setName(e.target.value)} />
          <TextInput label="Default timezone (IANA)" placeholder={details.data?.settings.timezone ?? "e.g. Asia/Kolkata"} value={timezone} onChange={(e) => setTimezone(e.target.value)} hint="Used as the default for scheduled scans." />
          {save.error && <Notice tone="error">{errorMessage(save.error)}</Notice>}
          {save.isSuccess && <Notice tone="ok">Saved.</Notice>}
          <Button type="submit" variant="primary" busy={save.isPending}>Save</Button>
        </form>
      ) : <Notice>Only owners and administrators can change organization settings.</Notice>}
      {org.can("org.archive") && (
        <Section title={org.status === "archived" ? "Restore organization" : "Archive organization"} className="mt-10">
          <p className="mb-3 text-[13px] text-muted">Archiving makes the organization read-only for every member. Data is kept, and owners can restore it.</p>
          <Button variant={org.status === "archived" ? "secondary" : "danger"} onClick={() => setArchiving(true)}>{org.status === "archived" ? "Restore" : "Archive organization…"}</Button>
          <ConfirmDialog open={archiving} danger={org.status !== "archived"} title={org.status === "archived" ? "Restore organization?" : "Archive organization?"} busy={archive.isPending}
            onCancel={() => setArchiving(false)} onConfirm={() => archive.mutate()}>This affects every member of {org.name}.</ConfirmDialog>
        </Section>
      )}
    </div>
  );
}

export function PolicyPage() {
  const org = useOrg();
  const queryClient = useQueryClient();
  const policy = useQuery({ queryKey: ["policy", org.id], queryFn: () => api.get<Policy>(`/organizations/${org.id}/policy`) });
  const history = useQuery({ queryKey: ["policy-history", org.id], queryFn: () => api.get<{ items: { version: number; reason: string; changed_by: string | null; created_at: string }[] }>(`/organizations/${org.id}/policy/history`) });
  const rules = useQuery({ queryKey: ["rules"], queryFn: () => api.get<{ items: Rule[]; ruleset_version: string }>("/rules") });
  const [draft, setDraft] = useState<Partial<PolicyConfig> | null>(null);
  const [reason, setReason] = useState("");
  const [disable, setDisable] = useState({ rule: "", why: "" });
  const save = useMutation({
    mutationFn: (changes: Partial<PolicyConfig>) => api.put(`/organizations/${org.id}/policy`, { changes, reason }),
    onSuccess: () => { setDraft(null); setReason(""); void queryClient.invalidateQueries({ queryKey: ["policy", org.id] }); void queryClient.invalidateQueries({ queryKey: ["policy-history", org.id] }); },
  });
  if (policy.isLoading) return <Skeleton rows={8} />;
  if (policy.error || !policy.data) return <ErrorState error={policy.error} />;
  const config = { ...policy.data.config, ...(draft ?? {}) } as PolicyConfig;
  const edit = (patch: Partial<PolicyConfig>) => setDraft({ ...(draft ?? {}), ...patch });
  const editable = policy.data.can_edit;
  return (
    <>
      <PageHeader title="Security policy" description={`Version ${policy.data.version}. Changes are versioned and audited, and apply to scans queued after the change.`} />
      {!editable && <div className="mb-4"><Notice>Read-only: only owners, administrators and security administrators can change the policy.</Notice></div>}
      <div className="grid gap-6 md:grid-cols-3">
        <Select label="Record findings at or above severity" disabled={!editable} value={config.minimum_severity} onChange={(e) => edit({ minimum_severity: e.target.value as PolicyConfig["minimum_severity"] })} options={["info", "low", "medium", "high", "critical"].map((s) => ({ value: s, label: humanize(s) }))} />
        <Select label="Minimum confidence" disabled={!editable} value={config.minimum_confidence} onChange={(e) => edit({ minimum_confidence: e.target.value })} options={["low", "medium", "high"].map((s) => ({ value: s, label: humanize(s) }))} />
        <Select label="Fail pull-request checks at" disabled={!editable} value={config.pr_fail_severity ?? ""} onChange={(e) => edit({ pr_fail_severity: (e.target.value || null) as PolicyConfig["pr_fail_severity"] })} options={[{ value: "", label: "Never block (informational)" }, ...["critical", "high", "medium", "low"].map((s) => ({ value: s, label: `${humanize(s)} or above` }))]} />
        <TextInput label="Max file size (bytes)" type="number" disabled={!editable} value={config.max_file_bytes} onChange={(e) => edit({ max_file_bytes: Number(e.target.value) })} />
        <TextInput label="Max archive size (bytes)" type="number" disabled={!editable} value={config.max_archive_bytes} onChange={(e) => edit({ max_archive_bytes: Number(e.target.value) })} />
        <TextInput label="Max scan duration (seconds)" type="number" disabled={!editable} value={config.max_scan_seconds} onChange={(e) => edit({ max_scan_seconds: Number(e.target.value) })} />
        <TextInput label="Accepted-risk maximum (days)" type="number" disabled={!editable} value={config.accepted_risk_max_days} onChange={(e) => edit({ accepted_risk_max_days: Number(e.target.value) })} />
        <div className="space-y-2 pt-5">
          <Checkbox label="Risk acceptance requires review" disabled={!editable} checked={config.accepted_risk_requires_review} onChange={(v) => edit({ accepted_risk_requires_review: v })} />
          <Checkbox label="False positives require review" disabled={!editable} checked={config.false_positive_requires_review} onChange={(v) => edit({ false_positive_requires_review: v })} />
        </div>
      </div>
      <div className="mt-6"><TextArea label="Excluded paths (glob, one per line)" disabled={!editable} value={config.excluded_paths.join("\n")} onChange={(e) => edit({ excluded_paths: e.target.value.split("\n").map((s) => s.trim()).filter(Boolean) })} /></div>
      {editable && draft && (
        <div className="mt-4 flex flex-wrap items-end gap-3">
          <div className="w-96"><TextInput label="Reason for change (audited)" value={reason} onChange={(e) => setReason(e.target.value)} /></div>
          <Button variant="primary" disabled={reason.length < 5} busy={save.isPending} onClick={() => save.mutate(draft)}>Save policy</Button>
          <Button variant="ghost" onClick={() => setDraft(null)}>Discard</Button>
        </div>
      )}
      {save.error && <div className="mt-3"><Notice tone="error">{errorMessage(save.error)}</Notice></div>}
      <Section title={`Rules (${rules.data?.items.length ?? 0}) · rule set ${rules.data?.ruleset_version ?? ""}`} className="mt-10">
        {editable && (
          <div className="mb-4 flex flex-wrap items-end gap-3">
            <div className="w-56"><Select label="Disable rule" value={disable.rule} onChange={(e) => setDisable({ ...disable, rule: e.target.value })} options={[{ value: "", label: "Select…" }, ...(rules.data?.items ?? []).filter((r) => !config.disabled_rules[r.id]).map((r) => ({ value: r.id, label: `${r.id} ${r.name}` }))]} /></div>
            <div className="w-80"><TextInput label="Justification" value={disable.why} onChange={(e) => setDisable({ ...disable, why: e.target.value })} /></div>
            <div className="w-64"><TextInput label="Reason for change (audited)" value={reason} onChange={(e) => setReason(e.target.value)} /></div>
            <Button disabled={!disable.rule || disable.why.length < 10 || reason.length < 5} onClick={() => { save.mutate({ disabled_rules: { ...config.disabled_rules, [disable.rule]: disable.why } }); setDisable({ rule: "", why: "" }); }}>Disable</Button>
          </div>
        )}
        <Table head={["Rule", "Severity", "CWE", "Languages", "Technique", "State"]}>
          {rules.data?.items.map((rule) => (
            <tr key={rule.id}>
              <td><Mono>{rule.id}</Mono> {rule.name}<div className="text-xs text-faint">{rule.description}</div></td>
              <td><SeverityBadge severity={rule.severity} /></td><td className="text-muted">{rule.cwe}</td><td className="text-muted">{rule.languages.join(", ")}</td>
              <td className="text-xs text-faint">{rule.technique}</td>
              <td>{config.disabled_rules[rule.id] ? <span className="text-medium" title={config.disabled_rules[rule.id]}>Disabled
                {editable && <button type="button" className="ml-2 text-xs text-accent" disabled={reason.length < 5} onClick={() => { const next = { ...config.disabled_rules }; delete next[rule.id]; save.mutate({ disabled_rules: next }); }}>re-enable</button>}</span> : "Enabled"}</td>
            </tr>
          ))}
        </Table>
      </Section>
      <Section title="Policy history" className="mt-8">
        <ul className="space-y-1 text-[13px]">{history.data?.items.map((h) => <li key={h.version}>v{h.version} · {dateTime(h.created_at)} · {h.changed_by ?? "system"} · <span className="text-muted">{h.reason}</span></li>)}</ul>
      </Section>
    </>
  );
}

export function IntegrationsPage() {
  const org = useOrg();
  const queryClient = useQueryClient();
  const [token, setToken] = useState("");
  const [created, setCreated] = useState<Integration | null>(null);
  const [browse, setBrowse] = useState<string | null>(null);
  const list = useQuery({ queryKey: ["integrations", org.id], queryFn: () => api.get<{ items: Integration[] }>(`/organizations/${org.id}/integrations`) });
  const repos = useQuery({ queryKey: ["repos", org.id, browse], queryFn: () => api.get<{ items: { full_name: string; private: boolean; default_branch: string }[] }>(`/organizations/${org.id}/integrations/${browse}/repositories`), enabled: !!browse, retry: false });
  const invalidate = () => queryClient.invalidateQueries({ queryKey: ["integrations", org.id] });
  const connect = useMutation({ mutationFn: () => api.post<Integration>(`/organizations/${org.id}/integrations/github`, { token, scan_pull_requests: true, publish_pr_results: true }), onSuccess: (i) => { setToken(""); setCreated(i); void invalidate(); } });
  const disconnect = useMutation({ mutationFn: (id: string) => api.delete(`/organizations/${org.id}/integrations/${id}`), onSuccess: invalidate });
  const toggle = useMutation({ mutationFn: ({ id, key, value }: { id: string; key: string; value: boolean }) => api.patch(`/organizations/${org.id}/integrations/${id}`, { [key]: value }), onSuccess: invalidate });
  const webhookUrl = (i: Integration) => `${window.location.origin}${i.webhook_url}`;
  return (
    <>
      <PageHeader title="GitHub integration" description="Connect with a fine-grained personal access token. The token is encrypted at rest, never returned to the browser, and only sent to api.github.com." />
      <Notice>Recommended token: fine-grained, limited to the repositories you want to scan, with <strong>Contents: read</strong> and <strong>Metadata: read</strong>. Add <strong>Commit statuses: write</strong> and <strong>Pull requests: write</strong> only if you want PR summaries posted. A GitHub App with per-installation tokens is on the roadmap; see docs/GITHUB-INTEGRATION.md for the trade-offs.</Notice>
      {org.can("integrations.manage") && (
        <form className="my-6 flex flex-wrap items-end gap-3" onSubmit={(e) => { e.preventDefault(); connect.mutate(); }}>
          <div className="w-96"><TextInput label="GitHub token" type="password" autoComplete="off" value={token} onChange={(e) => setToken(e.target.value)} required /></div>
          <Button type="submit" variant="primary" busy={connect.isPending}>Connect</Button>
        </form>
      )}
      {connect.error && <div className="mb-4"><Notice tone="error">{errorMessage(connect.error)}</Notice></div>}
      {created?.webhook_secret && (
        <div className="mb-6"><Notice tone="warning">
          Connected as {created.account_login}. To enable webhooks, add one in the repository settings (content type <Mono>application/json</Mono>, events: pushes and pull requests) with:
          <div className="mt-2">Payload URL: <Mono className="break-all">{webhookUrl(created)}</Mono></div>
          <div>Secret (shown once): <Mono className="break-all">{created.webhook_secret}</Mono></div>
        </Notice></div>
      )}
      {list.isLoading ? <Skeleton /> : list.data?.items.length === 0 ? <EmptyState title="No integrations">Projects can still be scanned from uploaded archives.</EmptyState> : (
        <div className="space-y-6">
          {list.data?.items.map((i) => (
            <Section key={i.id} title={`${i.account_login ?? "GitHub"} (${i.credential_hint ?? "no credential"})`} actions={<StatusBadge status={i.status} />}>
              {i.last_error && <div className="mb-2"><Notice tone="error">{i.last_error}</Notice></div>}
              <div className="flex flex-wrap gap-6 text-[13px]">
                {(["scan_pull_requests", "publish_pr_results", "auto_scan_push"] as const).map((key) => (
                  <Checkbox key={key} label={humanize(key)} checked={Boolean(i.settings[key])} disabled={!org.can("integrations.manage") || i.status === "revoked"} onChange={(value) => toggle.mutate({ id: i.id, key, value })} />
                ))}
              </div>
              <div className="mt-2 text-xs text-faint">Webhook endpoint: <Mono>{webhookUrl(i)}</Mono></div>
              <div className="mt-3 flex gap-2">
                {i.status !== "revoked" && <Button onClick={() => setBrowse(browse === i.id ? null : i.id)}>{browse === i.id ? "Hide repositories" : "Browse repositories"}</Button>}
                {org.can("integrations.manage") && i.status !== "revoked" && <Button variant="danger" onClick={() => disconnect.mutate(i.id)}>Disconnect &amp; delete token</Button>}
              </div>
              {browse === i.id && (repos.isLoading ? <Skeleton /> : repos.error ? <ErrorState error={repos.error} /> : (
                <ul className="mt-3 space-y-1 text-[13px]">{repos.data?.items.map((r) => <li key={r.full_name}><Mono>{r.full_name}</Mono> {r.private && <span className="text-xs text-faint">private</span>} · default <Mono>{r.default_branch}</Mono></li>)}</ul>
              ))}
            </Section>
          ))}
        </div>
      )}
      <p className="mt-6 text-xs text-faint">Create a GitHub project from <Link className="text-accent" to={`/orgs/${org.id}/projects?new=1`}>Projects → New project</Link>.</p>
    </>
  );
}

export function AuditLogPage() {
  const org = useOrg();
  const [action, setAction] = useState("");
  const [actor, setActor] = useState("");
  const [offset, setOffset] = useState(0);
  const { data, isLoading, error } = useQuery({ queryKey: ["audit", org.id, action, actor, offset], queryFn: () => api.get<Page<AuditEvent>>(`/organizations/${org.id}/audit-events`, { action, actor, limit: 50, offset }) });
  return (
    <>
      <PageHeader title="Audit log" description="Append-only, hash-chained record of security-relevant actions. No secrets or source code are logged."
        actions={<Button onClick={() => download(`/organizations/${org.id}/audit-events/export.csv`, { action }, "audit.csv")}>Export CSV</Button>} />
      <div className="mb-4 grid max-w-xl grid-cols-2 gap-3">
        <TextInput label="Action prefix" placeholder="finding." value={action} onChange={(e) => { setAction(e.target.value); setOffset(0); }} />
        <TextInput label="Actor email" value={actor} onChange={(e) => { setActor(e.target.value); setOffset(0); }} />
      </div>
      {isLoading && <Skeleton />}
      {error && <ErrorState error={error} />}
      {data && <>
        <Table head={["Time", "Action", "Actor", "Resource", "Details", "Request"]}>
          {data.items.map((e) => (
            <tr key={e.id}>
              <td className="whitespace-nowrap text-muted">{dateTime(e.created_at)}</td><td><Mono>{e.action}</Mono></td><td>{e.actor_email ?? "SecurCode"}</td>
              <td className="text-muted">{e.resource_type} <Mono>{e.resource_id?.slice(0, 8)}</Mono></td>
              <td className="max-w-xs truncate text-xs text-faint" title={JSON.stringify(e.metadata)}>{Object.keys(e.metadata).length ? JSON.stringify(e.metadata) : ""}</td>
              <td><Mono>{e.request_id?.slice(0, 8)}</Mono></td>
            </tr>
          ))}
        </Table>
        <Pagination total={data.total} limit={50} offset={offset} onChange={setOffset} />
      </>}
    </>
  );
}

const REPORTS = [
  ["organization", "Organization security report", "All active findings across projects."],
  ["project", "Project security report", "Scope, latest scan, posture and findings for one project."],
  ["vulnerability", "Vulnerability report", "Active findings with locations and owners."],
  ["remediation", "Remediation progress", "Verified fixes versus open work, assignments and overdue items."],
  ["risk_acceptance", "Risk acceptance report", "Accepted risks and false positives with justifications and expiry."],
  ["posture", "Security posture report", "Posture score inputs per project."],
] as const;

export function ReportsPage() {
  const org = useOrg();
  const [projectId, setProjectId] = useState("");
  const projects = useQuery({ queryKey: ["projects", org.id, "all"], queryFn: () => api.get<Page<Project>>(`/organizations/${org.id}/projects`, { limit: 200 }) });
  const url = (kind: string) => {
    // Only a known report kind and a hex project id ever reach the link.
    const safeKind = REPORTS.some(([k]) => k === kind) ? kind : "organization";
    const params = /^[a-f0-9]{32}$/.test(projectId) ? `?${new URLSearchParams({ project_id: projectId })}` : "";
    return `${API_BASE}/organizations/${encodeURIComponent(org.id)}/reports/${safeKind}${params}`;
  };
  return (
    <>
      <PageHeader title="Reports" description="Reports open as printable pages (use your browser's Print → Save as PDF) and include scope, scanner and rule-set versions, and limitations." />
      <div className="mb-6 w-80"><Select label="Project scope" value={projectId} onChange={(e) => setProjectId(e.target.value)} options={[{ value: "", label: "All projects" }, ...(projects.data?.items ?? []).map((p) => ({ value: p.id, label: p.name }))]} /></div>
      <div className="grid gap-px border border-line bg-line sm:grid-cols-2">
        {REPORTS.map(([kind, title, body]) => {
          const disabled = kind === "project" && !projectId;
          return (
            <div key={kind} className="bg-surface p-5">
              <h2 className="text-sm font-semibold">{title}</h2><p className="mt-1 text-[13px] text-muted">{body}</p>
              {disabled ? <p className="mt-3 text-xs text-faint">Select a project first.</p> : (
                <div className="mt-3 flex gap-3 text-[13px]">
                  <a className="text-accent" href={url(kind)} target="_blank" rel="noreferrer">Open printable report</a>
                  <button type="button" className="text-accent" onClick={() => download(`/organizations/${org.id}/reports/${kind}`, { format: "json", project_id: projectId || undefined }, `${kind}-report.json`)}>Download JSON</button>
                </div>
              )}
            </div>
          );
        })}
      </div>
      <p className="mt-6 text-xs text-faint">Scan and comparison reports are on each scan's page. Finding exports (CSV, JSON, SARIF 2.1.0) are on the Vulnerabilities page. Every export is recorded in the audit log.</p>
    </>
  );
}

export function SchedulesPage() {
  const org = useOrg();
  const queryClient = useQueryClient();
  const [form, setForm] = useState({ project_id: "", frequency: "weekly", hour: 2, minute: 0, weekday: 0, timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC", branch: "" });
  const schedules = useQuery({ queryKey: ["schedules", org.id], queryFn: () => api.get<{ items: Schedule[] }>(`/organizations/${org.id}/schedules`) });
  const projects = useQuery({ queryKey: ["projects", org.id, "all"], queryFn: () => api.get<Page<Project>>(`/organizations/${org.id}/projects`, { limit: 200 }) });
  const invalidate = () => queryClient.invalidateQueries({ queryKey: ["schedules", org.id] });
  const create = useMutation({ mutationFn: () => api.post(`/organizations/${org.id}/schedules`, { ...form, weekday: form.frequency === "weekly" ? form.weekday : null, branch: form.branch || null, enabled: false }), onSuccess: invalidate });
  const toggle = useMutation({ mutationFn: (s: Schedule) => api.patch(`/organizations/${org.id}/schedules/${s.id}`, { enabled: !s.enabled }), onSuccess: invalidate });
  const remove = useMutation({ mutationFn: (id: string) => api.delete(`/organizations/${org.id}/schedules/${id}`), onSuccess: invalidate });
  const names = Object.fromEntries((projects.data?.items ?? []).map((p) => [p.id, p.name]));
  const days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];
  return (
    <>
      <PageHeader title="Scheduled scans" description="Schedules are created disabled and run only after you enable them. The worker runs each due schedule exactly once." />
      {org.can("schedules.manage") && (
        <form className="mb-8 grid gap-3 border border-line bg-surface p-4 md:grid-cols-4" onSubmit={(e) => { e.preventDefault(); create.mutate(); }}>
          <Select label="Project" value={form.project_id} onChange={(e) => setForm({ ...form, project_id: e.target.value })} options={[{ value: "", label: "Select…" }, ...(projects.data?.items ?? []).filter((p) => p.status === "active").map((p) => ({ value: p.id, label: p.name }))]} />
          <Select label="Frequency" value={form.frequency} onChange={(e) => setForm({ ...form, frequency: e.target.value })} options={[{ value: "daily", label: "Daily" }, { value: "weekly", label: "Weekly" }]} />
          {form.frequency === "weekly" && <Select label="Day" value={String(form.weekday)} onChange={(e) => setForm({ ...form, weekday: Number(e.target.value) })} options={days.map((d, i) => ({ value: String(i), label: d }))} />}
          <TextInput label="Time (HH:MM)" type="time" value={`${String(form.hour).padStart(2, "0")}:${String(form.minute).padStart(2, "0")}`} onChange={(e) => { const [h, m] = e.target.value.split(":").map(Number); setForm({ ...form, hour: h, minute: m }); }} />
          <TextInput label="Timezone" value={form.timezone} onChange={(e) => setForm({ ...form, timezone: e.target.value })} />
          <TextInput label="Branch (GitHub projects)" value={form.branch} onChange={(e) => setForm({ ...form, branch: e.target.value })} />
          <div className="flex items-end"><Button type="submit" variant="primary" disabled={!form.project_id} busy={create.isPending}>Create (disabled)</Button></div>
          {create.error && <div className="md:col-span-4"><Notice tone="error">{errorMessage(create.error)}</Notice></div>}
        </form>
      )}
      {schedules.isLoading ? <Skeleton /> : schedules.data?.items.length === 0 ? <EmptyState title="No scheduled scans" /> : (
        <Table head={["Project", "When", "Next run", "Last run", "Recent results", ""]}>
          {schedules.data?.items.map((s) => (
            <tr key={s.id}>
              <td>{names[s.project_id] ?? s.project_id.slice(0, 8)}{s.branch && <div className="text-xs text-faint">branch {s.branch}</div>}</td>
              <td>{s.frequency === "weekly" ? days[s.weekday ?? 0] : "Daily"} {String(s.hour).padStart(2, "0")}:{String(s.minute).padStart(2, "0")} <span className="text-xs text-faint">{s.timezone}</span></td>
              <td className="text-muted">{s.enabled ? dateTime(s.next_run_at) : "Disabled"}</td>
              <td className="text-muted">{dateTime(s.last_run_at)}{s.last_error && <div className="text-xs text-critical">{s.last_error}</div>}</td>
              <td className="space-x-1">{s.history.slice(0, 5).map((h) => <Link key={h.scan_id} to={`/orgs/${org.id}/scans/${h.scan_id}`}><StatusBadge status={h.status} /></Link>)}</td>
              <td className="whitespace-nowrap text-right">{org.can("schedules.manage") && <><Button variant="ghost" onClick={() => toggle.mutate(s)}>{s.enabled ? "Disable" : "Enable"}</Button><Button variant="ghost" onClick={() => remove.mutate(s.id)}>Delete</Button></>}</td>
            </tr>
          ))}
        </Table>
      )}
    </>
  );
}
