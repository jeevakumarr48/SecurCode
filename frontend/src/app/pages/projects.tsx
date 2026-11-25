import { useRef, useState, type FormEvent } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, errorMessage } from "../lib/api";
import { useOrg } from "../lib/auth";
import { timeAgo } from "../lib/format";
import type { Integration, Member, Page, Project, Scan } from "../lib/types";
import {
  Button, ConfirmDialog, DemoBanner, EmptyState, ErrorState, Mono, Notice, PageHeader, Pagination, Section, Select, Skeleton,
  StatusBadge, Table, Tabs, TextArea, TextInput,
} from "../components/ui";
import { ScanTable } from "../components/ScanTable";

export function ProjectsPage() {
  const org = useOrg();
  const [params, setParams] = useSearchParams();
  const [search, setSearch] = useState("");
  const [status, setStatus] = useState("active");
  const [sort, setSort] = useState("name");
  const [offset, setOffset] = useState(0);
  const creating = params.get("new") === "1";
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["projects", org.id, search, status, sort, offset],
    queryFn: () => api.get<Page<Project>>(`/organizations/${org.id}/projects`, { search, status, sort, limit: 25, offset }),
  });
  return (
    <>
      <PageHeader title="Projects" description="Each project is a codebase that SecurCode scans: an uploaded archive, a GitHub repository, or a bundled test fixture."
        actions={org.can("projects.create") && !creating ? <Button variant="primary" onClick={() => setParams({ new: "1" })}>New project</Button> : undefined} />
      <DemoBanner show={org.is_demo} />
      {creating && <CreateProject onDone={() => setParams({})} />}
      <div className="mb-4 grid gap-3 sm:grid-cols-[1fr_160px_200px]">
        <TextInput label="Search" placeholder="Project name" value={search} onChange={(e) => { setSearch(e.target.value); setOffset(0); }} />
        <Select label="Status" value={status} onChange={(e) => setStatus(e.target.value)} options={[{ value: "active", label: "Active" }, { value: "archived", label: "Archived" }, { value: "", label: "All" }]} />
        <Select label="Sort" value={sort} onChange={(e) => setSort(e.target.value)} options={[
          { value: "name", label: "Name" }, { value: "-last_scan_at", label: "Recently scanned" }, { value: "-created_at", label: "Newest" }]} />
      </div>
      {isLoading && <Skeleton />}
      {error && <ErrorState error={error} retry={refetch} />}
      {data && (data.items.length === 0 ? (
        <EmptyState title={search ? "No projects match" : "No projects yet"}>{org.can("projects.create") ? "Create a project to start scanning." : "Ask an administrator to add you to a project."}</EmptyState>
      ) : (
        <>
          <Table head={["Project", "Source", "Languages", "Active findings", "Posture", "Last scan", "Status"]}>
            {data.items.map((project) => (
              <tr key={project.id}>
                <td><Link className="font-medium text-accent" to={`/orgs/${org.id}/projects/${project.id}`}>{project.name}</Link>
                  {project.description && <div className="max-w-xs truncate text-xs text-faint">{project.description}</div>}</td>
                <td className="text-muted">{project.repository_full_name ?? (project.source_type === "fixture" ? `fixture: ${project.fixture_name}` : "archive upload")}</td>
                <td className="text-muted">{project.languages.join(", ") || "—"}</td>
                <td className="tabular">{project.active_findings.total}
                  {(project.active_findings.critical ?? 0) > 0 && <span className="ml-1 text-xs text-critical">{project.active_findings.critical} critical</span>}</td>
                <td className="tabular">{project.posture.score ?? "—"}</td>
                <td>{project.last_scan ? <><StatusBadge status={project.last_scan.status} /> <span className="text-xs text-faint">{timeAgo(project.last_scan.created_at)}</span></> : <span className="text-faint">Never</span>}</td>
                <td><StatusBadge status={project.status} /></td>
              </tr>
            ))}
          </Table>
          <Pagination total={data.total} limit={data.limit} offset={data.offset} onChange={setOffset} />
        </>
      ))}
    </>
  );
}

function CreateProject({ onDone }: { onDone: () => void }) {
  const org = useOrg();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [form, setForm] = useState({ name: "", description: "", source_type: "upload", repository_full_name: "", integration_id: "", default_branch: "main", fixture_name: "" });
  const [error, setError] = useState<string | null>(null);
  const integrations = useQuery({ queryKey: ["integrations", org.id], queryFn: () => api.get<{ items: Integration[] }>(`/organizations/${org.id}/integrations`), enabled: org.can("integrations.view") });
  const fixtures = useQuery({ queryKey: ["fixtures", org.id], queryFn: () => api.get<{ items: string[] }>(`/organizations/${org.id}/fixtures`) });
  const create = useMutation({
    mutationFn: () => api.post<Project>(`/organizations/${org.id}/projects`, {
      name: form.name, description: form.description, source_type: form.source_type, default_branch: form.default_branch,
      ...(form.source_type === "github" ? { repository_full_name: form.repository_full_name, integration_id: form.integration_id } : {}),
      ...(form.source_type === "fixture" ? { fixture_name: form.fixture_name } : {}),
    }),
    onSuccess: (project) => { void queryClient.invalidateQueries({ queryKey: ["projects", org.id] }); onDone(); navigate(`/orgs/${org.id}/projects/${project.id}`); },
    onError: (err) => setError(errorMessage(err)),
  });
  const activeIntegrations = (integrations.data?.items ?? []).filter((i) => i.status !== "revoked");
  return (
    <form className="mb-8 space-y-4 border border-line bg-surface p-5" onSubmit={(event: FormEvent) => { event.preventDefault(); create.mutate(); }}>
      <h2 className="text-sm font-semibold">New project</h2>
      {error && <Notice tone="error">{error}</Notice>}
      <div className="grid gap-4 md:grid-cols-2">
        <TextInput label="Name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required minLength={2} autoFocus />
        <Select label="Source" value={form.source_type} onChange={(e) => setForm({ ...form, source_type: e.target.value })} options={[
          { value: "upload", label: "Upload source archive (.zip / .tar.gz)" }, { value: "github", label: "GitHub repository" }, { value: "fixture", label: "Bundled test fixture" }]} />
      </div>
      <TextArea label="Description" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
      {form.source_type === "github" && (activeIntegrations.length === 0 ? (
        <Notice tone="warning">Connect a GitHub integration first under <Link className="underline" to={`/orgs/${org.id}/integrations`}>GitHub integration</Link>.</Notice>
      ) : (
        <div className="grid gap-4 md:grid-cols-3">
          <Select label="Integration" value={form.integration_id} onChange={(e) => setForm({ ...form, integration_id: e.target.value })}
            options={[{ value: "", label: "Select…" }, ...activeIntegrations.map((i) => ({ value: i.id, label: `${i.account_login} (${i.credential_hint})` }))]} />
          <TextInput label="Repository (owner/name)" placeholder="acme/payments-api" value={form.repository_full_name} onChange={(e) => setForm({ ...form, repository_full_name: e.target.value })} />
          <TextInput label="Default branch" value={form.default_branch} onChange={(e) => setForm({ ...form, default_branch: e.target.value })} />
        </div>
      ))}
      {form.source_type === "fixture" && (
        <Select label="Fixture" value={form.fixture_name} onChange={(e) => setForm({ ...form, fixture_name: e.target.value })}
          options={[{ value: "", label: "Select…" }, ...(fixtures.data?.items ?? []).map((f) => ({ value: f, label: f }))]}
          hint="Intentionally vulnerable sample code shipped with SecurCode, for demos and testing." />
      )}
      <div className="flex gap-2">
        <Button type="submit" variant="primary" busy={create.isPending}>Create project</Button>
        <Button variant="ghost" onClick={onDone}>Cancel</Button>
      </div>
    </form>
  );
}

type Tab = "overview" | "scans" | "members" | "activity" | "settings";

export function ProjectDetailPage() {
  const org = useOrg();
  const { projectId = "" } = useParams();
  const [tab, setTab] = useState<Tab>("overview");
  const { data: project, isLoading, error, refetch } = useQuery({
    queryKey: ["project", org.id, projectId],
    queryFn: () => api.get<Project>(`/organizations/${org.id}/projects/${projectId}`),
  });
  if (isLoading) return <Skeleton rows={6} />;
  if (error || !project) return <ErrorState error={error} retry={refetch} />;
  return (
    <>
      <PageHeader eyebrow={<Link to={`/orgs/${org.id}/projects`} className="hover:text-fg">Projects</Link>} title={project.name}
        description={project.description || undefined} actions={<StatusBadge status={project.status} />} />
      <Tabs value={tab} onChange={setTab} tabs={[
        { value: "overview", label: "Overview" }, { value: "scans", label: "Scan history" }, { value: "members", label: "Members" },
        { value: "activity", label: "Activity" }, ...(org.can("projects.manage") ? [{ value: "settings" as Tab, label: "Settings" }] : [])]} />
      {tab === "overview" && <ProjectOverview project={project} />}
      {tab === "scans" && <ProjectScans project={project} />}
      {tab === "members" && <ProjectMembers project={project} />}
      {tab === "activity" && <ProjectActivity project={project} />}
      {tab === "settings" && <ProjectSettings project={project} />}
    </>
  );
}

function ProjectOverview({ project }: { project: Project }) {
  const org = useOrg();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const fileRef = useRef<HTMLInputElement>(null);
  const [branch, setBranch] = useState(project.default_branch);
  const [error, setError] = useState<string | null>(null);
  const start = useMutation({
    mutationFn: async () => {
      if (project.source_type === "upload") {
        const file = fileRef.current?.files?.[0];
        if (!file) throw new Error("Choose a .zip or .tar.gz archive first.");
        return api.upload<Scan>(`/organizations/${org.id}/projects/${project.id}/scans/upload`, file);
      }
      return api.post<Scan>(`/organizations/${org.id}/projects/${project.id}/scans`, project.source_type === "github" ? { branch } : {},
        { "Idempotency-Key": `ui-${project.id}-${Date.now()}` });
    },
    onSuccess: (scan) => { void queryClient.invalidateQueries({ queryKey: ["project", org.id, project.id] }); navigate(`/orgs/${org.id}/scans/${scan.id}`); },
    onError: (err) => setError(errorMessage(err)),
  });
  return (
    <div className="space-y-8">
      <div className="grid grid-cols-2 gap-6 md:grid-cols-5">
        {(["critical", "high", "medium", "low"] as const).map((severity) => (
          <div key={severity} className="border-l border-line pl-3"><div className="text-xs capitalize text-muted">{severity}</div><div className="tabular text-2xl font-semibold">{project.active_findings[severity] ?? 0}</div></div>
        ))}
        <div className="border-l border-line pl-3"><div className="text-xs text-muted">Posture</div><div className="tabular text-2xl font-semibold">{project.posture.score ?? "—"}</div>
          <div className="text-[11px] text-faint">{project.posture.grade ? `Grade ${project.posture.grade}` : project.posture.reason}</div></div>
      </div>
      {project.status === "active" && org.can("scans.run") && (
        <Section title="Run a scan">
          {error && <div className="mb-3"><Notice tone="error">{error}</Notice></div>}
          <div className="flex flex-wrap items-end gap-3">
            {project.source_type === "upload" && (
              <div className="space-y-1">
                <label htmlFor="archive" className="block text-xs font-medium text-muted">Source archive</label>
                <input id="archive" ref={fileRef} type="file" accept=".zip,.tar.gz,.tgz,application/zip,application/gzip" className="text-[13px] text-muted file:mr-3 file:rounded-[3px] file:border file:border-line file:bg-raised file:px-3 file:py-1.5 file:text-fg" />
                <p className="text-xs text-faint">Code is unpacked in an isolated workspace and read as text. It is never executed or installed.</p>
              </div>
            )}
            {project.source_type === "github" && <div className="w-64"><TextInput label="Branch" value={branch} onChange={(e) => setBranch(e.target.value)} /></div>}
            {project.source_type === "fixture" && <p className="text-[13px] text-muted">Scans the bundled fixture <Mono>{project.fixture_name}</Mono>.</p>}
            <Button variant="primary" busy={start.isPending} onClick={() => { setError(null); start.mutate(); }}>Start scan</Button>
          </div>
        </Section>
      )}
      <Section title="Details">
        <dl className="grid gap-x-8 gap-y-2 text-[13px] sm:grid-cols-[180px_1fr]">
          <dt className="text-muted">Source</dt><dd>{project.repository_url ? <a className="text-accent" href={project.repository_url} rel="noreferrer noopener" target="_blank">{project.repository_full_name}</a> : project.source_type}</dd>
          <dt className="text-muted">Default branch</dt><dd><Mono>{project.default_branch}</Mono></dd>
          <dt className="text-muted">Languages</dt><dd>{project.languages.join(", ") || "Detected on first scan"}</dd>
          <dt className="text-muted">Last scan</dt><dd>{project.last_scan ? <Link className="text-accent" to={`/orgs/${org.id}/scans/${project.last_scan.id}`}>{timeAgo(project.last_scan.created_at)}</Link> : "Never"}</dd>
          <dt className="text-muted">Findings</dt><dd><Link className="text-accent" to={`/orgs/${org.id}/findings?project_id=${project.id}`}>View {project.active_findings.total} active findings</Link></dd>
        </dl>
      </Section>
    </div>
  );
}

function ProjectScans({ project }: { project: Project }) {
  const org = useOrg();
  const [offset, setOffset] = useState(0);
  const { data, isLoading, error } = useQuery({
    queryKey: ["scans", org.id, project.id, offset],
    queryFn: () => api.get<Page<Scan>>(`/organizations/${org.id}/scans`, { project_id: project.id, limit: 20, offset }),
    refetchInterval: 10_000,
  });
  if (isLoading) return <Skeleton />;
  if (error) return <ErrorState error={error} />;
  return data ? <><ScanTable scans={data.items} orgId={org.id} /><Pagination total={data.total} limit={20} offset={offset} onChange={setOffset} /></> : null;
}

function ProjectMembers({ project }: { project: Project }) {
  const org = useOrg();
  const queryClient = useQueryClient();
  const [userId, setUserId] = useState("");
  const [role, setRole] = useState("contributor");
  const members = useQuery({ queryKey: ["members", org.id], queryFn: () => api.get<{ items: Member[] }>(`/organizations/${org.id}/members`), enabled: org.can("projects.manage") });
  const refresh = () => queryClient.invalidateQueries({ queryKey: ["project", org.id, project.id] });
  const add = useMutation({ mutationFn: () => api.post(`/organizations/${org.id}/projects/${project.id}/members`, { user_id: userId, role }), onSuccess: refresh });
  const remove = useMutation({ mutationFn: (id: string) => api.delete(`/organizations/${org.id}/projects/${project.id}/members/${id}`), onSuccess: refresh });
  const current = new Set(project.members?.map((m) => m.user_id));
  return (
    <div className="space-y-6">
      <Notice>Owners, administrators and security staff see every project. Developers and viewers see only the projects they are members of.</Notice>
      <Table head={["Member", "Project role", ""]}>
        {project.members?.map((member) => (
          <tr key={member.user_id}><td>{member.display_name} <span className="text-xs text-faint">{member.email}</span></td><td>{member.role}</td>
            <td className="text-right">{org.can("projects.manage") && <Button variant="ghost" onClick={() => remove.mutate(member.user_id)}>Remove</Button>}</td></tr>
        ))}
      </Table>
      {org.can("projects.manage") && (
        <div className="flex flex-wrap items-end gap-3">
          <div className="w-72"><Select label="Add organization member" value={userId} onChange={(e) => setUserId(e.target.value)}
            options={[{ value: "", label: "Select…" }, ...(members.data?.items ?? []).filter((m) => !current.has(m.user_id)).map((m) => ({ value: m.user_id, label: `${m.email} (${m.role})` }))]} /></div>
          <div className="w-40"><Select label="Role" value={role} onChange={(e) => setRole(e.target.value)} options={["maintainer", "contributor", "viewer"].map((r) => ({ value: r, label: r }))} /></div>
          <Button variant="primary" disabled={!userId} busy={add.isPending} onClick={() => add.mutate()}>Add</Button>
        </div>
      )}
      {add.error && <Notice tone="error">{errorMessage(add.error)}</Notice>}
    </div>
  );
}

function ProjectActivity({ project }: { project: Project }) {
  const org = useOrg();
  const { data, isLoading } = useQuery({
    queryKey: ["project-activity", org.id, project.id],
    queryFn: () => api.get<{ items: { action: string; actor_email: string | null; created_at: string; resource_type: string | null }[] }>(`/organizations/${org.id}/projects/${project.id}/activity`),
  });
  if (isLoading) return <Skeleton />;
  return (
    <Table head={["When", "Action", "Actor"]} empty={!data?.items.length}>
      {data?.items.map((event, index) => <tr key={index}><td className="text-muted">{timeAgo(event.created_at)}</td><td><Mono>{event.action}</Mono></td><td>{event.actor_email ?? "SecurCode"}</td></tr>)}
    </Table>
  );
}

function ProjectSettings({ project }: { project: Project }) {
  const org = useOrg();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [form, setForm] = useState({ name: project.name, description: project.description, default_branch: project.default_branch });
  const [confirm, setConfirm] = useState("");
  const [deleting, setDeleting] = useState(false);
  const refresh = () => queryClient.invalidateQueries({ queryKey: ["project", org.id, project.id] });
  const save = useMutation({ mutationFn: () => api.patch(`/organizations/${org.id}/projects/${project.id}`, form), onSuccess: refresh });
  const archive = useMutation({ mutationFn: () => api.post(`/organizations/${org.id}/projects/${project.id}/${project.status === "active" ? "archive" : "restore"}`), onSuccess: refresh });
  const remove = useMutation({
    mutationFn: () => api.delete(`/organizations/${org.id}/projects/${project.id}`, { confirm_name: confirm }),
    onSuccess: () => { void queryClient.invalidateQueries({ queryKey: ["projects", org.id] }); navigate(`/orgs/${org.id}/projects`); },
  });
  return (
    <div className="max-w-2xl space-y-8">
      <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); save.mutate(); }}>
        <TextInput label="Name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
        <TextArea label="Description" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
        <TextInput label="Default branch" value={form.default_branch} onChange={(e) => setForm({ ...form, default_branch: e.target.value })} />
        {save.error && <Notice tone="error">{errorMessage(save.error)}</Notice>}
        {save.isSuccess && <Notice tone="ok">Saved.</Notice>}
        <Button type="submit" variant="primary" busy={save.isPending}>Save changes</Button>
      </form>
      <Section title="Archive">
        <p className="mb-3 text-[13px] text-muted">Archived projects keep their history but cannot be scanned.</p>
        <Button busy={archive.isPending} onClick={() => archive.mutate()}>{project.status === "active" ? "Archive project" : "Restore project"}</Button>
      </Section>
      {org.can("projects.delete") && (
        <Section title="Delete project">
          <p className="mb-3 text-[13px] text-muted">Permanently deletes the project, its scans, findings and uploaded archives. The deletion is recorded in the audit log.</p>
          <Button variant="danger" onClick={() => setDeleting(true)}>Delete project…</Button>
          <ConfirmDialog open={deleting} danger title={`Delete ${project.name}?`} confirmLabel="Delete permanently" busy={remove.isPending}
            confirmDisabled={confirm !== project.name} onCancel={() => setDeleting(false)} onConfirm={() => remove.mutate()}>
            <p className="mb-3">This cannot be undone. Type the project name to confirm.</p>
            <TextInput label="Project name" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
            {remove.error && <div className="mt-2"><Notice tone="error">{errorMessage(remove.error)}</Notice></div>}
          </ConfirmDialog>
        </Section>
      )}
    </div>
  );
}
