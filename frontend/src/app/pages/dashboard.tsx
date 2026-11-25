import { Fragment, useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { Bar, BarChart, CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api, errorMessage } from "../lib/api";
import { useAuth, useOrg } from "../lib/auth";
import { duration, percent } from "../lib/format";
import type { Dashboard, OrgSummary, Page, Project, Scan } from "../lib/types";
import { Button, ButtonLink, DemoBanner, EmptyState, ErrorState, Notice, PageHeader, Section, Select, Skeleton, Stat, Table, TextInput } from "../components/ui";
import { ScanTable } from "../components/ScanTable";

export function OnboardingPage() {
  const { session, setSession, refresh } = useAuth();
  const navigate = useNavigate();
  const [name, setName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const org = await api.post<OrgSummary>("/organizations", { name });
      const payload = await refresh();
      if (payload) setSession(payload);
      navigate(`/orgs/${org.id}/projects?new=1`);
    } catch (err) { setError(errorMessage(err)); } finally { setBusy(false); }
  }
  return (
    <div className="mx-auto max-w-2xl">
      <PageHeader title="Set up your organization" description="Organizations keep their own members, projects, scans, findings and settings, fully separate from every other organization." />
      <ol className="mb-8 grid gap-3 text-[13px] text-muted sm:grid-cols-4">
        {["Create organization", "Create first project", "Upload code or connect GitHub", "Review & assign findings"].map((step, index) => (
          <li key={step} className={index === 0 ? "border-t-2 border-accent pt-2 text-fg" : "border-t border-line pt-2"}>{index + 1}. {step}</li>
        ))}
      </ol>
      <form onSubmit={submit} className="space-y-4 border border-line bg-surface p-5">
        {error && <Notice tone="error">{error}</Notice>}
        <TextInput label="Organization name" placeholder="Acme Engineering" value={name} onChange={(e) => setName(e.target.value)} minLength={2} required autoFocus />
        <Button type="submit" variant="primary" busy={busy}>Create organization</Button>
      </form>
      {session && session.organizations.length > 0 && (
        <Section title="Or continue with an existing organization" className="mt-8">
          <ul className="space-y-1">{session.organizations.map((org) => <li key={org.id}><Link className="text-accent" to={`/orgs/${org.id}/dashboard`}>{org.name}</Link></li>)}</ul>
        </Section>
      )}
      <p className="mt-6 text-xs text-faint">Invited to an existing team? Open the link in your invitation email instead.</p>
    </div>
  );
}

function useDashboard(projectId: string, days: number) {
  const org = useOrg();
  return useQuery({
    queryKey: ["dashboard", org.id, projectId, days],
    queryFn: () => api.get<Dashboard>(`/organizations/${org.id}/analytics/dashboard`, { project_id: projectId || undefined, days }),
    refetchInterval: 20_000,
  });
}

export function DashboardPage() {
  const org = useOrg();
  const { data, isLoading, error, refetch } = useDashboard("", 30);
  const recent = useQuery({
    queryKey: ["scans", org.id, "recent"],
    queryFn: () => api.get<Page<Scan>>(`/organizations/${org.id}/scans`, { limit: 6 }),
    refetchInterval: 10_000,
  });
  return (
    <>
      <PageHeader title="Security overview" description="Every figure is calculated from persisted scans and findings in this organization." actions={<ButtonLink to={`/orgs/${org.id}/projects`} variant="primary">Scan a project</ButtonLink>} />
      <DemoBanner show={org.is_demo} />
      {isLoading && <Skeleton rows={6} />}
      {error && <ErrorState error={error} retry={refetch} />}
      {data && data.totals.projects === 0 ? (
        <EmptyState title="No projects yet" action={org.can("projects.create") ? <ButtonLink to={`/orgs/${org.id}/projects?new=1`} variant="primary">Create your first project</ButtonLink> : undefined}>
          Create a project, upload a source archive or connect a GitHub repository, then run your first scan.
        </EmptyState>
      ) : data && (
        <div className="space-y-8">
          <div className="grid grid-cols-2 gap-6 md:grid-cols-4 lg:grid-cols-7">
            <Stat label="Active findings" value={data.totals.active_findings} />
            <Stat label="Critical" value={data.totals.critical} tone={data.totals.critical ? "critical" : undefined} />
            <Stat label="High" value={data.totals.high} tone={data.totals.high ? "high" : undefined} />
            <Stat label="Medium" value={data.totals.medium} tone={data.totals.medium ? "medium" : undefined} />
            <Stat label="Low" value={data.totals.low} tone={data.totals.low ? "low" : undefined} />
            <Stat label="Posture" value={data.posture.score ?? "—"} hint={data.posture.grade ? `Grade ${data.posture.grade}` : "Not assessed"} />
            <Stat label="Overdue" value={data.totals.overdue} tone={data.totals.overdue ? "high" : undefined} />
          </div>
          <div className="grid gap-8 lg:grid-cols-3">
            <Section title="Open findings, last 30 days" className="lg:col-span-2"><TrendChart data={data.trend} /></Section>
            <Section title="Activity (30 days)">
              <dl className="grid grid-cols-2 gap-y-3 text-[13px]">
                <dt className="text-muted">New findings</dt><dd className="tabular text-right">{data.totals.new_findings}</dd>
                <dt className="text-muted">Verified fixed</dt><dd className="tabular text-right text-ok">{data.totals.resolved_findings}</dd>
                <dt className="text-muted">Recurring</dt><dd className="tabular text-right">{data.totals.recurring_findings}</dd>
                <dt className="text-muted">Assigned tasks</dt><dd className="tabular text-right">{data.totals.open_remediation_tasks}</dd>
                <dt className="text-muted">Scan success rate</dt><dd className="tabular text-right">{percent(data.scan_health.success_rate)}</dd>
                <dt className="text-muted">Avg. scan time</dt><dd className="tabular text-right">{duration(data.scan_health.average_duration_ms)}</dd>
              </dl>
            </Section>
          </div>
          <Section title="Project posture" actions={<Link to={`/orgs/${org.id}/analytics`} className="text-xs text-accent">Formula & analytics</Link>}>
            <Table head={["Project", "Score", "Grade", "Active findings", "Last scan age"]}>
              {data.posture.projects.map((row) => (
                <tr key={row.project_id}>
                  <td><Link className="text-accent" to={`/orgs/${org.id}/projects/${row.project_id}`}>{row.name}</Link></td>
                  <td className="tabular">{row.score ?? "—"}</td><td>{row.grade ?? "Not assessed"}</td>
                  <td className="tabular">{row.active_findings}</td><td className="tabular">{row.last_scan_age_days !== undefined ? `${row.last_scan_age_days} d` : "—"}</td>
                </tr>
              ))}
            </Table>
          </Section>
          <Section title="Recent scans" actions={<Link to={`/orgs/${org.id}/scans`} className="text-xs text-accent">All scans</Link>}>
            {recent.data && <ScanTable scans={recent.data.items} orgId={org.id} />}
          </Section>
        </div>
      )}
    </>
  );
}

const axis = { stroke: "var(--faint)", fontSize: 11 };

function TrendChart({ data }: { data: Dashboard["trend"] }) {
  return (
    <div className="h-56" role="img" aria-label={`Open findings trend; latest value ${data.at(-1)?.open ?? 0}`}>
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={data} margin={{ left: -16, right: 8, top: 8 }}>
          <CartesianGrid stroke="var(--line-soft)" vertical={false} />
          <XAxis dataKey="date" tick={axis} tickLine={false} axisLine={{ stroke: "var(--line)" }} minTickGap={24} />
          <YAxis allowDecimals={false} tick={axis} tickLine={false} axisLine={false} />
          <Tooltip contentStyle={{ background: "var(--surface)", border: "1px solid var(--line)", fontSize: 12 }} />
          <Line type="monotone" dataKey="open" stroke="var(--accent)" strokeWidth={2} dot={false} name="Open" isAnimationActive={false} />
          <Line type="monotone" dataKey="new" stroke="var(--high)" strokeWidth={1} dot={false} name="New that day" isAnimationActive={false} />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}

function Distribution({ title, rows }: { title: string; rows: { name: string; count: number }[] }) {
  return (
    <Section title={title}>
      {rows.length === 0 ? <p className="text-[13px] text-muted">No active findings.</p> : (
        <div style={{ height: Math.max(rows.length * 28, 80) }}>
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={rows} layout="vertical" margin={{ left: 8, right: 16 }}>
              <XAxis type="number" allowDecimals={false} tick={axis} axisLine={false} tickLine={false} />
              <YAxis type="category" dataKey="name" width={170} tick={{ ...axis, fill: "var(--muted)" }} axisLine={false} tickLine={false} />
              <Tooltip cursor={{ fill: "var(--surface-raised)" }} contentStyle={{ background: "var(--surface)", border: "1px solid var(--line)", fontSize: 12 }} />
              <Bar dataKey="count" fill="var(--accent)" barSize={14} name="Active findings" isAnimationActive={false} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </Section>
  );
}

export function AnalyticsPage() {
  const org = useOrg();
  const [projectId, setProjectId] = useState("");
  const [days, setDays] = useState(90);
  const projects = useQuery({ queryKey: ["projects", org.id, "all"], queryFn: () => api.get<Page<Project>>(`/organizations/${org.id}/projects`, { limit: 200 }) });
  const { data, isLoading, error, refetch } = useDashboard(projectId, days);
  const mttr = useQuery({ queryKey: ["mttr", org.id], queryFn: () => api.get<{ days_by_severity: Record<string, number> }>(`/organizations/${org.id}/analytics/mttr`) });
  return (
    <>
      <PageHeader title="Security analytics" description="Trends and distributions over active findings. Filter by project and time window." />
      <div className="mb-6 grid max-w-lg grid-cols-2 gap-3">
        <Select label="Project" value={projectId} onChange={(e) => setProjectId(e.target.value)} options={[{ value: "", label: "All projects" }, ...(projects.data?.items ?? []).map((p) => ({ value: p.id, label: p.name }))]} />
        <Select label="Window" value={String(days)} onChange={(e) => setDays(Number(e.target.value))} options={[30, 90, 180, 365].map((d) => ({ value: String(d), label: `${d} days` }))} />
      </div>
      {isLoading && <Skeleton rows={8} />}
      {error && <ErrorState error={error} retry={refetch} />}
      {data && (
        <div className="space-y-8">
          <Section title="Open findings trend"><TrendChart data={data.trend} /></Section>
          <div className="grid gap-8 lg:grid-cols-2">
            <Distribution title="CWE distribution" rows={data.distribution.cwe} />
            <Distribution title="OWASP Top 10 (2021) category" rows={data.distribution.owasp} />
            <Distribution title="Language" rows={data.distribution.language} />
            <Section title="Remediation">
              <dl className="grid grid-cols-2 gap-y-2 text-[13px]">
                <dt className="text-muted">Remediated (fixed or verified)</dt><dd className="tabular text-right">{data.remediation_progress.remediated} / {data.remediation_progress.total}</dd>
                <dt className="text-muted">Progress</dt><dd className="tabular text-right">{percent(data.remediation_progress.ratio)}</dd>
                {Object.entries(mttr.data?.days_by_severity ?? {}).map(([severity, value]) => (
                  <Fragment key={severity}><dt className="text-muted">Mean time to verified fix ({severity})</dt><dd className="tabular text-right">{value} days</dd></Fragment>
                ))}
              </dl>
            </Section>
          </div>
          <Section title="How the posture score is calculated">
            <div className="space-y-2 text-[13px] text-muted">
              <p>Each active finding adds risk = severity weight (critical 10, high 5, medium 2, low 0.5) × confidence (high 1.0, medium 0.7, low 0.4) × age (1 + days open/90, capped at 2, +0.5 if overdue) × status (in progress 0.8, fixed awaiting verification 0.5).</p>
              <p>Score = 100 × e<sup>−risk/25</sup>, then multiplied by scan freshness (≤14 days 1.0, ≤30 days 0.85, older 0.7) and coverage (0.9 if the last scan completed with warnings). Projects with no successful scan are “not assessed”.</p>
              <p className="text-faint">This is an internal prioritisation signal derived only from SecurCode rules. It is not a certification and does not measure overall security. Formula: {data.posture.formula}.</p>
            </div>
          </Section>
        </div>
      )}
    </>
  );
}
