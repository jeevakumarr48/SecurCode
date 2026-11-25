import { useMemo, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, download, errorMessage } from "../lib/api";
import { useOrg } from "../lib/auth";
import { dateTime, humanize, timeAgo } from "../lib/format";
import type { Finding, FindingDetail, FindingStatus, Member, Page, Project, Review } from "../lib/types";
import {
  Button, Checkbox, DemoBanner, EmptyState, ErrorState, Mono, Notice, PageHeader, Pagination, Section, Select, SeverityBadge, Skeleton,
  StatusBadge, Table, TextArea, TextInput,
} from "../components/ui";

const STATUSES: FindingStatus[] = ["open", "triaged", "in_progress", "fixed", "reopened", "resolved", "accepted_risk", "false_positive"];
const ACTIVE: FindingStatus[] = ["open", "triaged", "in_progress", "fixed", "reopened"];

function useMembers(enabled = true) {
  const org = useOrg();
  return useQuery({ queryKey: ["members", org.id], queryFn: () => api.get<{ items: Member[] }>(`/organizations/${org.id}/members`), enabled });
}

export function FindingsPage({ mine = false }: { mine?: boolean }) {
  const org = useOrg();
  const queryClient = useQueryClient();
  const [params] = useSearchParams();
  const [filters, setFilters] = useState({
    project_id: params.get("project_id") ?? "", status: mine ? "active" : "active", severity: "", search: "", assignee: mine ? "me" : "", sort: "severity", overdue: false,
  });
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [bulk, setBulk] = useState({ status: "", assignee_id: "", label: "", justification: "" });
  const [notice, setNotice] = useState<string | null>(null);
  const projects = useQuery({ queryKey: ["projects", org.id, "all"], queryFn: () => api.get<Page<Project>>(`/organizations/${org.id}/projects`, { limit: 200 }) });
  const members = useMembers(org.can("findings.triage"));
  const query = useMemo(() => ({
    project_id: filters.project_id || undefined,
    status: filters.status === "active" ? ACTIVE : filters.status ? [filters.status] : undefined,
    severity: filters.severity ? [filters.severity] : undefined,
    search: filters.search, assignee: filters.assignee || undefined, sort: filters.sort, overdue: filters.overdue || undefined, limit: 50, offset,
  }), [filters, offset]);
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["findings", org.id, query],
    queryFn: () => api.get<Page<Finding>>(`/organizations/${org.id}/findings`, query),
  });
  const bulkUpdate = useMutation({
    mutationFn: () => api.post<{ updated: string[]; failed: { id: string; detail: string }[] }>(`/organizations/${org.id}/findings/bulk`, {
      finding_ids: [...selected], status: bulk.status || undefined, assignee_id: bulk.assignee_id || undefined,
      add_labels: bulk.label ? [bulk.label] : undefined, justification: bulk.justification || undefined,
    }),
    onSuccess: (result) => {
      setNotice(`${result.updated.length} updated${result.failed.length ? `, ${result.failed.length} skipped (${result.failed[0].detail})` : ""}.`);
      setSelected(new Set());
      void queryClient.invalidateQueries({ queryKey: ["findings", org.id] });
    },
    onError: (err) => setNotice(errorMessage(err)),
  });
  const set = (patch: Partial<typeof filters>) => { setFilters({ ...filters, ...patch }); setOffset(0); };
  const allOnPage = data?.items.every((f) => selected.has(f.id)) && (data?.items.length ?? 0) > 0;
  return (
    <>
      <PageHeader title={mine ? "My remediation" : "Vulnerabilities"}
        description={mine ? "Findings assigned to you. Mark them in progress or fixed; a complete rescan verifies the fix." : "Deduplicated findings tracked across scans."}
        actions={org.can("reports.export") && !mine ? <>
          <Button onClick={() => download(`/organizations/${org.id}/exports/findings`, { format: "csv", project_id: query.project_id, status: query.status }, "findings.csv")}>Export CSV</Button>
          <Button onClick={() => download(`/organizations/${org.id}/exports/findings`, { format: "json", project_id: query.project_id, status: query.status }, "findings.json")}>JSON</Button>
          <Button onClick={() => download(`/organizations/${org.id}/exports/findings`, { format: "sarif", project_id: query.project_id, status: query.status }, "findings.sarif")}>SARIF</Button>
        </> : undefined} />
      <DemoBanner show={org.is_demo} />
      <div className="mb-4 grid gap-3 md:grid-cols-3 xl:grid-cols-6">
        <TextInput label="Search" placeholder="Title, path or rule" value={filters.search} onChange={(e) => set({ search: e.target.value })} />
        <Select label="Project" value={filters.project_id} onChange={(e) => set({ project_id: e.target.value })} options={[{ value: "", label: "All projects" }, ...(projects.data?.items ?? []).map((p) => ({ value: p.id, label: p.name }))]} />
        <Select label="Status" value={filters.status} onChange={(e) => set({ status: e.target.value })} options={[{ value: "active", label: "Active (unresolved)" }, { value: "", label: "Any status" }, ...STATUSES.map((s) => ({ value: s, label: humanize(s) }))]} />
        <Select label="Severity" value={filters.severity} onChange={(e) => set({ severity: e.target.value })} options={[{ value: "", label: "Any severity" }, ...["critical", "high", "medium", "low"].map((s) => ({ value: s, label: humanize(s) }))]} />
        {!mine && <Select label="Assignee" value={filters.assignee} onChange={(e) => set({ assignee: e.target.value })} options={[{ value: "", label: "Anyone" }, { value: "me", label: "Me" }, { value: "none", label: "Unassigned" }, ...(members.data?.items ?? []).map((m) => ({ value: m.user_id, label: m.email }))]} />}
        <Select label="Sort" value={filters.sort} onChange={(e) => set({ sort: e.target.value })} options={[{ value: "severity", label: "Severity" }, { value: "-first_detected_at", label: "Newest" }, { value: "first_detected_at", label: "Oldest" }, { value: "due_date", label: "Due date" }, { value: "file_path", label: "File" }]} />
      </div>
      <div className="mb-4"><Checkbox label="Overdue only" checked={filters.overdue} onChange={(v) => set({ overdue: v })} /></div>
      {notice && <div className="mb-3"><Notice>{notice}</Notice></div>}
      {selected.size > 0 && org.can("findings.triage") && (
        <div className="mb-4 flex flex-wrap items-end gap-3 border border-accent/40 bg-accent-soft/30 p-3">
          <span className="self-center text-[13px]">{selected.size} selected</span>
          <div className="w-40"><Select label="Set status" value={bulk.status} onChange={(e) => setBulk({ ...bulk, status: e.target.value })} options={[{ value: "", label: "—" }, ...["triaged", "in_progress", "open"].map((s) => ({ value: s, label: humanize(s) }))]} /></div>
          <div className="w-56"><Select label="Assign to" value={bulk.assignee_id} onChange={(e) => setBulk({ ...bulk, assignee_id: e.target.value })} options={[{ value: "", label: "—" }, ...(members.data?.items ?? []).map((m) => ({ value: m.user_id, label: m.email }))]} /></div>
          <div className="w-40"><TextInput label="Add label" value={bulk.label} onChange={(e) => setBulk({ ...bulk, label: e.target.value })} /></div>
          <Button variant="primary" busy={bulkUpdate.isPending} disabled={!bulk.status && !bulk.assignee_id && !bulk.label} onClick={() => bulkUpdate.mutate()}>Apply</Button>
          <Button variant="ghost" onClick={() => setSelected(new Set())}>Clear</Button>
        </div>
      )}
      {isLoading && <Skeleton rows={8} />}
      {error && <ErrorState error={error} retry={refetch} />}
      {data && (data.items.length === 0 ? <EmptyState title="No findings match these filters">{mine ? "Nothing is assigned to you right now." : "Run a scan or broaden the filters."}</EmptyState> : (
        <>
          <Table head={[
            org.can("findings.triage") ? <input type="checkbox" aria-label="Select all on this page" checked={!!allOnPage} onChange={(e) => {
              const next = new Set(selected); data.items.forEach((f) => (e.target.checked ? next.add(f.id) : next.delete(f.id))); setSelected(next);
            }} /> : "", "Severity", "Finding", "Location", "Project", "Status", "Assignee", "Due"]}>
            {data.items.map((finding) => (
              <tr key={finding.id}>
                <td>{org.can("findings.triage") && <input type="checkbox" aria-label={`Select ${finding.title}`} checked={selected.has(finding.id)} onChange={(e) => {
                  const next = new Set(selected); if (e.target.checked) next.add(finding.id); else next.delete(finding.id); setSelected(next);
                }} />}</td>
                <td><SeverityBadge severity={finding.severity} /></td>
                <td className="max-w-sm"><Link className="text-accent" to={`/orgs/${org.id}/findings/${finding.id}`}>{finding.title}</Link>
                  <div className="text-xs text-faint">{finding.rule_id}{finding.cwe ? ` · ${finding.cwe}` : ""}{finding.recurrence_count ? ` · recurred ×${finding.recurrence_count}` : ""}{finding.labels.length ? ` · ${finding.labels.join(", ")}` : ""}</div></td>
                <td><Mono>{finding.file_path}:{finding.line ?? ""}</Mono></td>
                <td className="text-muted">{finding.project_name}</td>
                <td><StatusBadge status={finding.status} /></td>
                <td className="text-muted">{finding.assignee?.email ?? "—"}</td>
                <td className={finding.overdue ? "text-critical" : "text-muted"}>{finding.due_date ? new Date(finding.due_date).toLocaleDateString() : "—"}</td>
              </tr>
            ))}
          </Table>
          <Pagination total={data.total} limit={50} offset={offset} onChange={setOffset} />
        </>
      ))}
    </>
  );
}

export function FindingDetailPage() {
  const org = useOrg();
  const { findingId = "" } = useParams();
  const queryClient = useQueryClient();
  const key = ["finding", org.id, findingId];
  const { data: finding, isLoading, error, refetch } = useQuery({ queryKey: key, queryFn: () => api.get<FindingDetail>(`/organizations/${org.id}/findings/${findingId}`) });
  const members = useMembers(org.can("findings.triage"));
  const [comment, setComment] = useState("");
  const [justification, setJustification] = useState("");
  const [severity, setSeverity] = useState({ value: "", reason: "" });
  const [review, setReview] = useState({ kind: "", justification: "" });
  const [notes, setNotes] = useState<string | null>(null);
  const [message, setMessage] = useState<{ tone: "ok" | "error"; text: string } | null>(null);
  const refresh = () => queryClient.invalidateQueries({ queryKey: key });
  const update = useMutation({
    mutationFn: (body: Record<string, unknown>) => api.patch(`/organizations/${org.id}/findings/${findingId}`, body),
    onSuccess: () => { setMessage({ tone: "ok", text: "Saved." }); setJustification(""); void refresh(); void queryClient.invalidateQueries({ queryKey: ["findings", org.id] }); },
    onError: (err) => setMessage({ tone: "error", text: errorMessage(err) }),
  });
  const addComment = useMutation({ mutationFn: () => api.post(`/organizations/${org.id}/findings/${findingId}/comments`, { body: comment }), onSuccess: () => { setComment(""); void refresh(); } });
  const requestReview = useMutation({
    mutationFn: () => api.post(`/organizations/${org.id}/findings/${findingId}/reviews`, review),
    onSuccess: () => { setReview({ kind: "", justification: "" }); setMessage({ tone: "ok", text: "Review requested from a security administrator." }); void refresh(); },
    onError: (err) => setMessage({ tone: "error", text: errorMessage(err) }),
  });
  if (isLoading) return <Skeleton rows={8} />;
  if (error || !finding) return <ErrorState error={error} retry={refetch} />;
  const g = finding.guidance;
  const pending = finding.reviews.find((r) => r.status === "pending");
  const reviewed = (s: string) => s === "accepted_risk" || s === "false_positive";
  return (
    <>
      <PageHeader eyebrow={<><Link to={`/orgs/${org.id}/findings`} className="hover:text-fg">Vulnerabilities</Link> / <Link to={`/orgs/${org.id}/projects/${finding.project_id}`} className="hover:text-fg">{finding.project_name}</Link></>}
        title={finding.title} description={<><Mono>{finding.file_path}:{finding.line ?? ""}</Mono> · {finding.rule_id}{finding.cwe ? ` · ${finding.cwe}` : ""}</>}
        actions={<><SeverityBadge severity={finding.severity} /><StatusBadge status={finding.status} /></>} />
      {message && <div className="mb-4"><Notice tone={message.tone}>{message.text}</Notice></div>}
      <div className="grid gap-8 lg:grid-cols-[1fr_340px]">
        <div className="space-y-8">
          <Section title="Where it occurs">
            {finding.snippet ? <pre className="overflow-x-auto border border-line bg-inset p-3 font-mono text-[12px] leading-relaxed text-fg">{finding.snippet}</pre> : <p className="text-[13px] text-muted">No code context stored.</p>}
            <p className="mt-2 text-xs text-faint">Secret-looking values are redacted before storage. {finding.verification_status !== "unverified" && <>Verification: <strong>{humanize(finding.verification_status)}</strong>.</>}</p>
          </Section>
          <Section title="What it means and how to fix it">
            <div className="space-y-3 text-[13px]">
              {g.meaning && <p><span className="text-muted">Issue: </span>{g.meaning}</p>}
              {g.why_it_matters && <p><span className="text-muted">Impact: </span>{g.why_it_matters}</p>}
              {g.recommended_fix && <p><span className="text-muted">Recommended fix: </span>{g.recommended_fix}</p>}
              {g.safer_example && <pre className="overflow-x-auto border border-ok/30 bg-ok-soft p-2 font-mono text-[12px] text-fg">{g.safer_example}</pre>}
              {g.validation_steps && <div><div className="text-muted">Validate the fix:</div><ol className="list-decimal pl-5">{g.validation_steps.map((s) => <li key={s}>{s}</li>)}</ol></div>}
              {g.false_positive_considerations && <p className="text-muted">False-positive considerations: {g.false_positive_considerations}</p>}
              <p className="text-xs text-faint">Detection: {g.detection_technique}. {g.owasp}. Guidance is rule-based and deterministic. {finding.ai_assistance.reason}</p>
              <div className="flex flex-wrap gap-3 text-xs">{g.references?.map((r) => <a key={r} className="text-accent" href={r} target="_blank" rel="noreferrer noopener">{r.replace(/^https?:\/\//, "")}</a>)}</div>
            </div>
          </Section>
          <Section title="Activity">
            <ol className="space-y-3">
              {finding.events.map((event) => (
                <li key={event.id} className="border-l border-line pl-3 text-[13px]">
                  <div className="text-xs text-faint">{event.actor} · {timeAgo(event.created_at)} · {humanize(event.kind)}{event.from || event.to ? `: ${event.from ?? "—"} → ${event.to ?? "—"}` : ""}</div>
                  {event.body && <p className="whitespace-pre-wrap">{event.body}</p>}
                </li>
              ))}
            </ol>
            {org.can("findings.comment") && (
              <form className="mt-4 space-y-2" onSubmit={(e) => { e.preventDefault(); addComment.mutate(); }}>
                <TextArea label="Add a comment" value={comment} onChange={(e) => setComment(e.target.value)} />
                <Button type="submit" busy={addComment.isPending} disabled={!comment.trim()}>Comment</Button>
              </form>
            )}
          </Section>
        </div>
        <aside className="space-y-6">
          <Section title="Status">
            {finding.allowed_transitions.length === 0 ? <p className="text-[13px] text-muted">{org.can("findings.remediate") && !org.can("findings.triage") ? "Only the assignee can update remediation status." : "No status changes available to you."}</p> : (
              <div className="space-y-2">
                <div className="flex flex-wrap gap-2">
                  {finding.allowed_transitions.filter((s) => !reviewed(s)).map((status) => (
                    <Button key={status} busy={update.isPending} onClick={() => update.mutate({ status })}>{humanize(status)}</Button>
                  ))}
                </div>
                {finding.allowed_transitions.some(reviewed) && (
                  <div className="space-y-2 border-t border-line pt-2">
                    <TextArea label="Justification (accepted risk / false positive)" value={justification} onChange={(e) => setJustification(e.target.value)} hint="At least 20 characters; recorded permanently." />
                    <div className="flex gap-2">{finding.allowed_transitions.filter(reviewed).map((status) => (
                      <Button key={status} disabled={justification.trim().length < 20} onClick={() => update.mutate({ status, justification })}>{humanize(status)}</Button>
                    ))}</div>
                  </div>
                )}
              </div>
            )}
            <p className="mt-2 text-xs text-faint">"Resolved" is set only by a complete rescan that no longer detects the finding.</p>
          </Section>
          {org.can("findings.triage") && (
            <Section title="Assignment">
              <div className="space-y-3">
                <Select label="Assignee" value={finding.assignee_id ?? ""} onChange={(e) => update.mutate(e.target.value ? { assignee_id: e.target.value } : { unassign: true })}
                  options={[{ value: "", label: "Unassigned" }, ...(members.data?.items ?? []).map((m) => ({ value: m.user_id, label: `${m.email} (${m.role})` }))]} />
                <TextInput label="Due date" type="date" value={finding.due_date?.slice(0, 10) ?? ""} onChange={(e) => update.mutate(e.target.value ? { due_date: `${e.target.value}T23:59:00Z` } : { clear_due_date: true })} />
                <TextInput label="Labels (comma separated)" defaultValue={finding.labels.join(", ")} onBlur={(e) => update.mutate({ labels: e.target.value.split(",").map((s) => s.trim()).filter(Boolean) })} />
              </div>
            </Section>
          )}
          {(org.can("findings.triage") || finding.assignee_id) && (
            <Section title="Remediation notes">
              <TextArea label="Notes" value={notes ?? finding.remediation_notes ?? ""} onChange={(e) => setNotes(e.target.value)} />
              <Button className="mt-2" disabled={notes === null} onClick={() => update.mutate({ remediation_notes: notes })}>Save notes</Button>
            </Section>
          )}
          {org.can("findings.severity") && (
            <Section title="Override severity">
              <div className="space-y-2">
                <Select label={`Severity (detected: ${finding.original_severity})`} value={severity.value || finding.severity} onChange={(e) => setSeverity({ ...severity, value: e.target.value })}
                  options={["critical", "high", "medium", "low", "info"].map((s) => ({ value: s, label: humanize(s) }))} />
                <TextInput label="Reason" value={severity.reason} onChange={(e) => setSeverity({ ...severity, reason: e.target.value })} />
                <Button disabled={!severity.value || severity.value === finding.severity || severity.reason.length < 10} onClick={() => update.mutate({ severity: severity.value, severity_reason: severity.reason })}>Change severity</Button>
              </div>
            </Section>
          )}
          {org.can("reviews.request") && !pending && ACTIVE.includes(finding.status) && (
            <Section title="Request review">
              <div className="space-y-2">
                <Select label="Request" value={review.kind} onChange={(e) => setReview({ ...review, kind: e.target.value })} options={[{ value: "", label: "Select…" }, { value: "accepted_risk", label: "Risk acceptance" }, { value: "false_positive", label: "False positive" }]} />
                <TextArea label="Justification" value={review.justification} onChange={(e) => setReview({ ...review, justification: e.target.value })} hint="A reviewer other than you must approve it." />
                <Button disabled={!review.kind || review.justification.length < 20} busy={requestReview.isPending} onClick={() => requestReview.mutate()}>Submit for review</Button>
              </div>
            </Section>
          )}
          {finding.reviews.length > 0 && (
            <Section title="Reviews">
              <ul className="space-y-2 text-[13px]">{finding.reviews.map((r) => (
                <li key={r.id} className="border-l border-line pl-3"><StatusBadge status={r.status} /> {humanize(r.kind)}<div className="text-xs text-faint">{r.requested_by} → {r.reviewer ?? "pending"}{r.expires_at ? ` · expires ${new Date(r.expires_at).toLocaleDateString()}` : ""}</div><p className="text-muted">{r.justification}</p></li>
              ))}</ul>
            </Section>
          )}
          <Section title="History">
            <dl className="space-y-1 text-[13px]">
              <dt className="text-muted">First detected</dt><dd>{dateTime(finding.first_detected_at)}{finding.first_scan_id && <> · <Link className="text-accent" to={`/orgs/${org.id}/scans/${finding.first_scan_id}`}>scan</Link></>}</dd>
              <dt className="text-muted">Last detected</dt><dd>{dateTime(finding.last_detected_at)}</dd>
              {finding.fixed_scan_id && <><dt className="text-muted">Verified fixed by</dt><dd><Link className="text-accent" to={`/orgs/${org.id}/scans/${finding.fixed_scan_id}`}>scan {finding.fixed_scan_id.slice(0, 8)}</Link></dd></>}
              <dt className="text-muted">Confidence</dt><dd>{finding.confidence}</dd>
              <dt className="text-muted">Fingerprint</dt><dd><Mono>{finding.fingerprint?.slice(0, 16)}</Mono></dd>
            </dl>
          </Section>
        </aside>
      </div>
    </>
  );
}

export function ReviewsPage() {
  const org = useOrg();
  const queryClient = useQueryClient();
  const [status, setStatus] = useState("pending");
  const [notes, setNotes] = useState<Record<string, string>>({});
  const { data, isLoading, error } = useQuery({ queryKey: ["reviews", org.id, status], queryFn: () => api.get<{ items: Review[] }>(`/organizations/${org.id}/reviews`, { status }) });
  const decide = useMutation({
    mutationFn: ({ id, approve }: { id: string; approve: boolean }) => api.post(`/organizations/${org.id}/reviews/${id}/decision`, { approve, note: notes[id] ?? "" }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["reviews", org.id] }),
  });
  return (
    <>
      <PageHeader title="Risk acceptance & false-positive reviews" description="Requests need approval from someone other than the requester. Approved risk acceptances expire automatically, and the finding then reopens." />
      <div className="mb-4 w-48"><Select label="Status" value={status} onChange={(e) => setStatus(e.target.value)} options={["pending", "approved", "rejected", "expired", "all"].map((s) => ({ value: s, label: humanize(s) }))} /></div>
      {decide.error && <div className="mb-3"><Notice tone="error">{errorMessage(decide.error)}</Notice></div>}
      {isLoading && <Skeleton />}
      {error && <ErrorState error={error} />}
      {data && (data.items.length === 0 ? <EmptyState title="No reviews" /> : (
        <Table head={["Finding", "Type", "Justification", "Requested", "Status", ""]}>
          {data.items.map((r) => (
            <tr key={r.id}>
              <td><Link className="text-accent" to={`/orgs/${org.id}/findings/${r.finding_id}`}>{r.finding_title}</Link>{r.severity && <div className="mt-1"><SeverityBadge severity={r.severity} /></div>}</td>
              <td>{humanize(r.kind)}{r.expires_at && <div className="text-xs text-faint">until {new Date(r.expires_at).toLocaleDateString()}</div>}</td>
              <td className="max-w-md text-muted">{r.justification}</td>
              <td className="text-muted">{r.requested_by}<div className="text-xs">{timeAgo(r.created_at)}</div></td>
              <td><StatusBadge status={r.status} />{r.reviewer && <div className="text-xs text-faint">{r.reviewer}</div>}</td>
              <td className="min-w-52">{r.status === "pending" && org.can("reviews.approve") && (
                <div className="space-y-2">
                  <TextInput label="Reviewer note" value={notes[r.id] ?? ""} onChange={(e) => setNotes({ ...notes, [r.id]: e.target.value })} />
                  <div className="flex gap-2"><Button variant="primary" onClick={() => decide.mutate({ id: r.id, approve: true })}>Approve</Button><Button variant="danger" onClick={() => decide.mutate({ id: r.id, approve: false })}>Reject</Button></div>
                </div>
              )}</td>
            </tr>
          ))}
        </Table>
      ))}
    </>
  );
}
