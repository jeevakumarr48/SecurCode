import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { API_BASE, api, download, errorMessage } from "../lib/api";
import { useOrg } from "../lib/auth";
import { dateTime, duration } from "../lib/format";
import type { CompareItem, Comparison, Page, Scan, Severity } from "../lib/types";
import { Button, EmptyState, ErrorState, Mono, Notice, PageHeader, Pagination, Section, Select, SeverityBadge, Skeleton, Stat, StatusBadge, Table } from "../components/ui";
import { ScanTable } from "../components/ScanTable";

const ACTIVE = new Set(["queued", "running"]);

export function ScansPage() {
  const org = useOrg();
  const [status, setStatus] = useState("");
  const [offset, setOffset] = useState(0);
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["scans", org.id, status, offset],
    queryFn: () => api.get<Page<Scan>>(`/organizations/${org.id}/scans`, { status, limit: 25, offset }),
    refetchInterval: (query) => (query.state.data?.items.some((s) => ACTIVE.has(s.status)) ? 3000 : 15_000),
  });
  return (
    <>
      <PageHeader title="Scans" description="Scans run in the background worker. This list updates automatically while scans are queued or running." />
      <div className="mb-4 w-56"><Select label="Status" value={status} onChange={(e) => { setStatus(e.target.value); setOffset(0); }}
        options={[{ value: "", label: "All" }, ...["queued", "running", "completed", "completed_with_warnings", "failed", "cancelled"].map((s) => ({ value: s, label: s.replaceAll("_", " ") }))]} /></div>
      {isLoading && <Skeleton />}
      {error && <ErrorState error={error} retry={refetch} />}
      {data && <><ScanTable scans={data.items} orgId={org.id} /><Pagination total={data.total} limit={25} offset={offset} onChange={setOffset} /></>}
    </>
  );
}

export function ScanDetailPage() {
  const org = useOrg();
  const { scanId = "" } = useParams();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [compareWith, setCompareWith] = useState("");
  const { data: scan, isLoading, error, refetch } = useQuery({
    queryKey: ["scan", org.id, scanId],
    queryFn: () => api.get<Scan & { project_name: string }>(`/organizations/${org.id}/scans/${scanId}`),
    refetchInterval: (query) => (query.state.data && ACTIVE.has(query.state.data.status) ? 2000 : false),
  });
  const findings = useQuery({
    queryKey: ["scan-findings", org.id, scanId, scan?.status],
    queryFn: () => api.get<{ total: number; items: { finding_id: string; rule_id: string; title: string; severity: Severity; file_path: string; line: number | null; status: string; is_new: boolean }[] }>(`/organizations/${org.id}/scans/${scanId}/findings`, { limit: 200 }),
    enabled: !!scan && !ACTIVE.has(scan.status),
  });
  const history = useQuery({
    queryKey: ["scans", org.id, scan?.project_id, "for-compare"],
    queryFn: () => api.get<Page<Scan>>(`/organizations/${org.id}/scans`, { project_id: scan!.project_id, limit: 50 }),
    enabled: !!scan,
  });
  const cancel = useMutation({ mutationFn: () => api.post(`/organizations/${org.id}/scans/${scanId}/cancel`), onSuccess: () => refetch() });
  const rescan = useMutation({
    mutationFn: () => api.post<Scan>(`/organizations/${org.id}/scans/${scanId}/rescan`),
    onSuccess: (next) => { void queryClient.invalidateQueries({ queryKey: ["scans", org.id] }); navigate(`/orgs/${org.id}/scans/${next.id}`); },
  });
  const [exportError, setExportError] = useState<string | null>(null);
  if (isLoading) return <Skeleton rows={6} />;
  if (error || !scan) return <ErrorState error={error} retry={refetch} />;
  const done = !ACTIVE.has(scan.status);
  const comparable = (history.data?.items ?? []).filter((s) => s.id !== scan.id && ["completed", "completed_with_warnings"].includes(s.status));
  return (
    <>
      <PageHeader eyebrow={<><Link to={`/orgs/${org.id}/projects/${scan.project_id}`} className="hover:text-fg">{scan.project_name}</Link> / scan</>}
        title={`Scan ${scan.id.slice(0, 8)}`}
        description={<>{scan.trigger} · {scan.source_type}{scan.branch ? <> · branch <Mono>{scan.branch}</Mono></> : null}{scan.commit_sha ? <> · commit <Mono>{scan.commit_sha.slice(0, 12)}</Mono></> : null}{scan.pull_request_number ? ` · PR #${scan.pull_request_number}` : ""}</>}
        actions={<>
          <StatusBadge status={scan.status} />
          {!done && org.can("scans.cancel") && <Button variant="danger" busy={cancel.isPending} onClick={() => cancel.mutate()}>Cancel scan</Button>}
          {done && org.can("scans.run") && <Button busy={rescan.isPending} onClick={() => rescan.mutate()}>Rescan</Button>}
          {done && org.can("reports.export") && <Button onClick={() => download(`/organizations/${org.id}/exports/findings`, { format: "sarif", scan_id: scan.id }, "scan.sarif").catch((e) => setExportError(errorMessage(e)))}>Export SARIF</Button>}
          {done && <a className="inline-flex items-center rounded-[3px] border border-line px-3 py-1.5 text-[13px] hover:border-accent" target="_blank" rel="noreferrer" href={`${API_BASE}/organizations/${org.id}/reports/scan?scan_id=${scan.id}`}>Printable report</a>}
        </>} />
      {exportError && <div className="mb-4"><Notice tone="error">{exportError}</Notice></div>}
      {!done && (
        <div className="mb-8 space-y-2" aria-live="polite">
          <div className="flex justify-between text-[13px]"><span>{scan.progress_message}</span><span className="tabular text-muted">{scan.progress}%</span></div>
          <div className="h-1.5 w-full bg-raised" role="progressbar" aria-valuenow={scan.progress} aria-valuemin={0} aria-valuemax={100}>
            <div className="h-full bg-accent transition-all" style={{ width: `${scan.progress}%` }} />
          </div>
          {scan.status === "queued" && <p className="text-xs text-faint">Waiting for a background worker. If this does not start, check that the worker process is running.</p>}
        </div>
      )}
      {scan.status === "failed" && <div className="mb-6"><Notice tone="error"><strong>Scan failed:</strong> {scan.error_message} No results from this scan were used to resolve findings.</Notice></div>}
      {scan.status === "completed_with_warnings" && <div className="mb-6"><Notice tone="warning">Completed with warnings. Coverage was incomplete, so findings that were not detected are <strong>not</strong> marked fixed. See the warnings below.</Notice></div>}
      {scan.is_clean && <div className="mb-6"><Notice tone="ok">Complete scan with no findings from the enabled rules. This is not proof the code is secure; see the rule coverage limits in the documentation.</Notice></div>}
      {done && scan.status !== "failed" && scan.status !== "cancelled" && (
        <div className="mb-8 grid grid-cols-2 gap-6 md:grid-cols-6">
          <Stat label="Findings" value={scan.summary.total ?? 0} />
          <Stat label="New" value={scan.summary.new ?? 0} tone={scan.summary.new ? "high" : undefined} />
          <Stat label="Verified fixed" value={scan.summary.resolved ?? 0} tone="ok" />
          <Stat label="Reopened" value={scan.summary.reopened ?? 0} />
          <Stat label="Files scanned" value={scan.files_scanned} />
          <Stat label="Duration" value={duration(scan.duration_ms)} />
        </div>
      )}
      <div className="grid gap-8 lg:grid-cols-[1fr_320px]">
        <div className="space-y-8">
          {done && findings.data && (
            <Section title={`Findings in this scan (${findings.data.total})`}>
              {findings.data.items.length === 0 ? <p className="text-[13px] text-muted">No findings recorded.</p> : (
                <Table head={["Severity", "Finding", "Location", "Status", ""]}>
                  {findings.data.items.map((item) => (
                    <tr key={item.finding_id}>
                      <td><SeverityBadge severity={item.severity} /></td>
                      <td><Link className="text-accent" to={`/orgs/${org.id}/findings/${item.finding_id}`}>{item.title}</Link><div className="text-xs text-faint">{item.rule_id}</div></td>
                      <td><Mono>{item.file_path}:{item.line ?? ""}</Mono></td>
                      <td><StatusBadge status={item.status} /></td>
                      <td>{item.is_new && <span className="text-xs text-high">new</span>}</td>
                    </tr>
                  ))}
                </Table>
              )}
            </Section>
          )}
          {scan.warnings.length > 0 && (
            <Section title={`Warnings (${scan.warnings.length})`}>
              <ul className="space-y-1 text-[13px]">{scan.warnings.map((w, i) => <li key={i}><Mono>{w.path}</Mono> {w.message}</li>)}</ul>
            </Section>
          )}
          <Section title="Scan log">
            <ol className="max-h-72 space-y-0.5 overflow-auto border border-line bg-inset p-3 font-mono text-[12px]">
              {(scan.logs ?? []).map((log, i) => <li key={i} className={log.level === "error" ? "text-critical" : log.level === "warning" ? "text-medium" : "text-muted"}>{new Date(log.at).toLocaleTimeString()} {log.message}</li>)}
            </ol>
          </Section>
        </div>
        <aside className="space-y-6">
          <Section title="Reproducibility">
            <dl className="space-y-1 text-[13px]">
              <dt className="text-muted">Scanner</dt><dd><Mono>{scan.scanner_version ?? "—"}</Mono></dd>
              <dt className="text-muted">Rule set</dt><dd><Mono>{scan.ruleset_version ?? "—"}</Mono> ({scan.rule_count} rules)</dd>
              <dt className="text-muted">Scope</dt><dd><Mono>{scan.scope_key}</Mono></dd>
              <dt className="text-muted">Queued</dt><dd>{dateTime(scan.created_at)}</dd>
              <dt className="text-muted">Finished</dt><dd>{dateTime(scan.finished_at)}</dd>
              {scan.summary.filtered_by_policy ? <><dt className="text-muted">Filtered by policy</dt><dd>{scan.summary.filtered_by_policy}</dd></> : null}
            </dl>
          </Section>
          {done && comparable.length > 0 && (
            <Section title="Compare with another scan">
              <div className="space-y-2">
                <Select label="Scan" value={compareWith} onChange={(e) => setCompareWith(e.target.value)}
                  options={[{ value: "", label: "Select…" }, ...comparable.map((s) => ({ value: s.id, label: `${s.id.slice(0, 8)} · ${dateTime(s.created_at)}` }))]} />
                <Button disabled={!compareWith} onClick={() => navigate(`/orgs/${org.id}/scans/${scan.id}/compare/${compareWith}`)}>Compare</Button>
              </div>
            </Section>
          )}
        </aside>
      </div>
    </>
  );
}

function CompareList({ title, items, orgId, extra }: { title: string; items: CompareItem[]; orgId: string; extra?: (item: CompareItem) => string }) {
  return (
    <Section title={`${title} (${items.length})`}>
      {items.length === 0 ? <p className="text-[13px] text-muted">None.</p> : (
        <Table head={["Severity", "Finding", "Location", "Current status"]}>
          {items.map((item) => (
            <tr key={item.finding_id}>
              <td><SeverityBadge severity={item.severity} /></td>
              <td><Link className="text-accent" to={`/orgs/${orgId}/findings/${item.finding_id}`}>{item.title}</Link><div className="text-xs text-faint">{item.rule_id}{extra ? ` · ${extra(item)}` : ""}</div></td>
              <td><Mono>{item.file_path}:{item.line ?? ""}</Mono></td>
              <td><StatusBadge status={item.current_status} /></td>
            </tr>
          ))}
        </Table>
      )}
    </Section>
  );
}

export function ScanComparePage() {
  const org = useOrg();
  const { scanId = "", otherId = "" } = useParams();
  const { data, isLoading, error } = useQuery({
    queryKey: ["compare", org.id, scanId, otherId],
    queryFn: () => api.get<Comparison>(`/organizations/${org.id}/scans/${scanId}/compare/${otherId}`),
  });
  if (isLoading) return <Skeleton rows={6} />;
  if (error || !data) return <ErrorState error={error} />;
  const columns = [["Baseline", data.base_scan], ["Compared", data.head_scan]] as const;
  return (
    <>
      <PageHeader eyebrow={<Link to={`/orgs/${org.id}/scans/${scanId}`}>Back to scan</Link>} title="Scan comparison" description="Findings are matched by content fingerprint, not by line number." />
      {data.warnings.length > 0
        ? <div className="mb-6"><Notice tone="warning"><strong>These scans are not fully equivalent.</strong><ul className="mt-1 list-disc pl-5">{data.warnings.map((w) => <li key={w}>{w}</li>)}</ul></Notice></div>
        : <div className="mb-6"><Notice tone="ok">Equivalent scans: same scope, scanner version, rule set and policy filters.</Notice></div>}
      <div className="mb-8 grid gap-6 md:grid-cols-2">
        {columns.map(([label, s]) => (
          <div key={label} className="border border-line p-4 text-[13px]">
            <div className="mb-2 text-xs uppercase tracking-wide text-faint">{label}</div>
            <Link className="font-mono text-accent" to={`/orgs/${org.id}/scans/${s.id}`}>{s.id.slice(0, 8)}</Link> · {dateTime(s.created_at)}
            <div className="mt-1 text-muted">{s.status.replaceAll("_", " ")} · {s.files_scanned} files · scanner {s.scanner_version} · scope {s.scope}{s.commit_sha ? ` · ${s.commit_sha.slice(0, 10)}` : ""}</div>
          </div>
        ))}
      </div>
      <div className="mb-8 grid grid-cols-2 gap-6 md:grid-cols-6">
        <Stat label="New" value={data.summary.new} tone={data.summary.new ? "high" : undefined} />
        <Stat label="Resolved" value={data.summary.resolved} tone="ok" />
        <Stat label="Recurring" value={data.summary.recurring} />
        <Stat label="Unchanged" value={data.summary.unchanged} />
        <Stat label="Severity changes" value={data.summary.severity_changes} />
        <Stat label="Out of rule scope" value={data.summary.no_longer_in_rule_scope} hint="Rule not run in the later scan" />
      </div>
      {(data.rule_coverage.added.length > 0 || data.rule_coverage.removed.length > 0) && (
        <div className="mb-6"><Notice>Rule coverage changed: +{data.rule_coverage.added.join(", ") || "none"} / −{data.rule_coverage.removed.join(", ") || "none"}</Notice></div>
      )}
      <div className="space-y-8">
        <CompareList title="New" items={data.new} orgId={org.id} />
        <CompareList title="Resolved" items={data.resolved} orgId={org.id} />
        <CompareList title="Recurring" items={data.recurring} orgId={org.id} />
        <CompareList title="Severity changes" items={data.severity_changes} orgId={org.id} extra={(i) => { const c = i as CompareItem & { from: string; to: string }; return `${c.from} → ${c.to}`; }} />
        <CompareList title="No longer in rule scope" items={data.no_longer_in_rule_scope} orgId={org.id} />
        {data.unchanged.length > 0 && <details><summary className="cursor-pointer text-[13px] text-muted">Unchanged ({data.unchanged.length})</summary><div className="mt-3"><CompareList title="Unchanged" items={data.unchanged} orgId={org.id} /></div></details>}
        {data.new.length + data.resolved.length + data.unchanged.length === 0 && <EmptyState title="Neither scan recorded findings" />}
      </div>
    </>
  );
}
