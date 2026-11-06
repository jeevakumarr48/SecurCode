import { useEffect, useMemo, useRef, useState } from "react";

const severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const findingStatuses = ["Open", "In Progress", "Resolved", "Accepted Risk", "False Positive"];
const incidentStatuses = ["Open", "Investigating", "Contained", "Resolved", "Closed"];

function EmptyState({ title, detail }) {
  return <div className="module-empty"><span className="section-label">No records</span><strong>{title}</strong><p>{detail}</p></div>;
}

function TableState({ loading, error, empty, children, columns }) {
  if (loading) return <div className="module-message" role="status">Loading records…</div>;
  if (error) return <div className="api-alert" role="alert"><div><strong>Could not load this section</strong><span>{error}</span></div></div>;
  if (empty) return <EmptyState title={empty.title} detail={empty.detail} />;
  return <div className="table-wrap"><table><thead><tr>{columns.map((column) => <th key={column}>{column}</th>)}</tr></thead><tbody>{children}</tbody></table></div>;
}

function StatusSelect({ value, values, onChange, disabled = false, label }) {
  return <select aria-label={label} value={value} disabled={disabled} onChange={(event) => onChange(event.target.value)}>{values.map((item) => <option key={item}>{item}</option>)}</select>;
}

export default function PlatformPage({ section, request, readOnly, role = "read_only", userId, downloadReport, onNavigate, onNotificationsChange, globalSearch = "" }) {
  const canManage = ["administrator", "security_analyst"].includes(role) && !readOnly;
  const canScan = ["administrator", "security_analyst", "developer"].includes(role) && !readOnly;
  const canContribute = ["administrator", "security_analyst", "developer"].includes(role) && !readOnly;
  const [records, setRecords] = useState(null);
  const [dashboard, setDashboard] = useState(null);
  const [integrationData, setIntegrationData] = useState(null);
  const [users, setUsers] = useState([]);
  const [userForm, setUserForm] = useState({ username: "", password: "", role: "developer" });
  const [passwordForm, setPasswordForm] = useState({ current_password: "", new_password: "" });
  const [assigneeInput, setAssigneeInput] = useState("");
  const [assignmentError, setAssignmentError] = useState("");
  const [assignmentSaving, setAssignmentSaving] = useState(false);
  const [commentInput, setCommentInput] = useState("");
  const [integrationTool, setIntegrationTool] = useState("bandit");
  const [integrationProjectId, setIntegrationProjectId] = useState("");
  const [status, setStatus] = useState({ loading: true, error: "" });
  const [notice, setNotice] = useState("");
  const [filter, setFilter] = useState("");
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");
  const [languageFilter, setLanguageFilter] = useState("");
  const [listQuery, setListQuery] = useState("");
  const [listFilter, setListFilter] = useState("");
  const [form, setForm] = useState({ name: "", project_path: "", description: "", owner: "", repository_url: "", default_branch: "main", title: "", priority: "Medium", finding_ref: null });
  const [busy, setBusy] = useState(false);
  const [selected, setSelected] = useState(null);
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [selectedProject, setSelectedProject] = useState(null);
  const [projectEdit, setProjectEdit] = useState(null);
  const [comparison, setComparison] = useState(null);
  const loadSequence = useRef(0);
  const assignmentSavingRef = useRef(false);

  async function load() {
    const sequence = ++loadSequence.current;
    setStatus({ loading: true, error: "" });
    try {
      let result;
      if (section === "Projects") result = await request("/projects?limit=100");
      else if (section === "Vulnerabilities") {
        const params = new URLSearchParams({ limit: "100" });
        if (filter) params.set("status", filter);
        if (search || globalSearch) params.set("search", search || globalSearch);
        if (severityFilter) params.set("severity", severityFilter);
        if (languageFilter) params.set("language", languageFilter);
        result = await request(`/findings?${params}`);
      }
      else if (section === "Incidents") {
        const params = new URLSearchParams({ limit: "100" });
        if (filter) params.set("status", filter);
        if (search) params.set("search", search);
        result = await request(`/incidents?${params}`);
      }
      else if (section === "Audit Logs") result = await request(`/audit?limit=100${search ? `&action=${encodeURIComponent(search)}` : ""}`);
      else if (section === "Notifications") result = await request("/notifications?limit=100");
      else if (section === "Integrations") {
        const [availability, projects] = await Promise.all([request("/integrations/status"), request("/projects?limit=100")]);
        result = { integrations: availability.integrations, projects: projects.projects };
        setIntegrationData(result);
      }
      else if (section === "Reports") result = await request("/reports/summary");
      else if (section === "Scans") result = await request("/history?limit=100");
      else if (section === "Access & Permissions" && role === "administrator") result = await request("/auth/users");
      else result = await request("/status");
      if (sequence !== loadSequence.current) return;
      if (section === "Reports") setDashboard(result);
      else if (section === "Access & Permissions" && role === "administrator") setUsers(result.users || []);
      else setRecords(result);
      setStatus({ loading: false, error: "" });
    } catch (error) {
      if (sequence !== loadSequence.current) return;
      setStatus({ loading: false, error: error.message });
    }
  }

  useEffect(() => { load(); }, [section, filter, search, severityFilter, languageFilter, role]);

  useEffect(() => {
    setFilter("");
    setSearch(globalSearch);
    setListQuery("");
    setListFilter("");
    setSeverityFilter("");
    setLanguageFilter("");
    setNotice("");
    setSelected(null);
    setSelectedIncident(null);
    setSelectedProject(null);
    setProjectEdit(null);
    setComparison(null);
  }, [section]);

  const title = section === "Vulnerabilities" ? "Vulnerability management" : section;
  const description = {
    Projects: "Register source trees and review their scan coverage.",
    Scans: "Launch a scan inside the configured workspace and review its recorded result.",
    Vulnerabilities: "Review evidence and track remediation state across stored scan findings.",
    Incidents: "Track response work linked to one or more detected findings.",
    "Audit Logs": "Review append-only records of scan and workflow changes.",
    Notifications: "Review scan, finding, assignment, and incident activity for this local workspace.",
    Reports: "Export persisted findings and inspect current workspace posture.",
    Configuration: "Review scan limits, filesystem boundaries, and service configuration.",
    Settings: "Review workspace preferences and available console settings.",
    "Access & Permissions": "Review the access controls available in this instance.",
  }[section] || "Workspace operations";

  async function submitProject(event) {
    event.preventDefault(); setBusy(true); setNotice("");
    try {
      await request("/projects", { method: "POST", body: JSON.stringify({ name: form.name, project_path: form.project_path, description: form.description, owner: form.owner || null, repository_url: form.repository_url || null, default_branch: form.default_branch }) });
      setForm((current) => ({ ...current, name: "", project_path: "", description: "", owner: "", repository_url: "", default_branch: "main" }));
      setNotice("Project registered."); await load();
    } catch (error) { setNotice(error.message); }
    finally { setBusy(false); }
  }

  async function submitUser(event) {
    event.preventDefault(); setBusy(true); setNotice("");
    try {
      await request("/auth/users", { method: "POST", body: JSON.stringify(userForm) });
      setUserForm({ username: "", password: "", role: "developer" });
      setNotice("Account created."); await load();
    } catch (error) { setNotice(error.message); }
    finally { setBusy(false); }
  }

  async function toggleUser(user) {
    setBusy(true); setNotice("");
    try {
      await request(`/auth/users/${user.id}`, { method: "PATCH", body: JSON.stringify({ disabled: !user.disabled }) });
      setNotice(user.disabled ? "Account enabled." : "Account disabled and active sessions revoked."); await load();
    } catch (error) { setNotice(error.message); }
    finally { setBusy(false); }
  }

  async function changeUserRole(user, role) {
    setBusy(true); setNotice("");
    try {
      await request(`/auth/users/${user.id}`, { method: "PATCH", body: JSON.stringify({ role }) });
      setNotice("Role updated."); await load();
    } catch (error) { setNotice(error.message); }
    finally { setBusy(false); }
  }

  async function changePassword(event) {
    event.preventDefault(); setBusy(true); setNotice("");
    try {
      await request("/auth/password", { method: "POST", body: JSON.stringify(passwordForm) });
      setPasswordForm({ current_password: "", new_password: "" });
      setNotice("Password changed. Other active sessions have been revoked.");
    } catch (error) { setNotice(error.message); }
    finally { setBusy(false); }
  }

  async function downloadFindingReport() {
    try { await downloadReport("/reports/findings.csv", "securcode-findings.csv"); }
    catch (error) { setNotice(error.message); }
  }

  async function submitScan(event) {
    event.preventDefault(); setBusy(true); setNotice("");
    try {
      const result = await request("/scan", { method: "POST", body: JSON.stringify({ project_path: form.project_path }) });
      setNotice(`Scan ${result.status}: ${result.total_findings} findings recorded.`); await load();
    } catch (error) { setNotice(error.message); }
    finally { setBusy(false); }
  }

  async function changeFindingStatus(finding, nextStatus) {
    setBusy(true); setNotice("");
    try {
      await request(`/findings/${finding.scan_id}/${finding.finding_index}/status`, { method: "PATCH", body: JSON.stringify({ status: nextStatus }) });
      setNotice("Finding status saved."); await load();
      if (selected?.scan_id === finding.scan_id && selected?.finding_index === finding.finding_index) {
        setSelected(await request(`/findings/${finding.scan_id}/${finding.finding_index}`));
      }
    } catch (error) { setNotice(error.message); }
    finally { setBusy(false); }
  }

  async function createIncident(event) {
    event.preventDefault(); setBusy(true); setNotice("");
    try {
      const body = { title: form.title, description: form.description, priority: form.priority };
      if (form.finding_ref) body.finding_refs = [form.finding_ref];
      await request("/incidents", { method: "POST", body: JSON.stringify(body) });
      setForm((current) => ({ ...current, title: "", description: "", finding_ref: null }));
      setNotice("Incident created and audit event recorded."); await load();
    } catch (error) { setNotice(error.message); }
    finally { setBusy(false); }
  }

  async function changeIncidentStatus(incident, nextStatus) {
    setBusy(true); setNotice("");
    try {
      await request(`/incidents/${incident.id}`, { method: "PATCH", body: JSON.stringify({ status: nextStatus }) });
      setNotice("Incident status saved."); await load();
    } catch (error) { setNotice(error.message); }
    finally { setBusy(false); }
  }

  async function inspectFinding(finding) {
    try {
      const detail = await request(`/findings/${finding.scan_id}/${finding.finding_index}`);
      setSelected(detail);
      setAssigneeInput(detail.assignee || "");
      setAssignmentError("");
      setCommentInput("");
    }
    catch (error) { setNotice(error.message); }
  }

  async function updateAssignee(event) {
    event.preventDefault();
    if (!selected || assignmentSavingRef.current) return;
    assignmentSavingRef.current = true;
    setAssignmentSaving(true);
    setAssignmentError("");
    setNotice("");
    try {
      const detail = await request(`/findings/${selected.scan_id}/${selected.finding_index}/assignee`, {
        method: "PATCH", body: JSON.stringify({ assignee: assigneeInput.trim() || null }),
      });
      setSelected(detail);
      setAssigneeInput(detail.assignee || "");
      setNotice(detail.assignee ? `Finding assigned to ${detail.assignee}.` : "Finding assignment cleared.");
      await load();
    } catch (error) {
      setAssignmentError(error.message);
    } finally {
      assignmentSavingRef.current = false;
      setAssignmentSaving(false);
    }
  }

  async function addComment(event) {
    event.preventDefault();
    if (!selected) return;
    setBusy(true); setNotice("");
    try {
      const scanId = selected.scan_id; const index = selected.finding_index;
      await request(`/findings/${scanId}/${index}/comments`, { method: "POST", body: JSON.stringify({ comment: commentInput }) });
      setSelected(await request(`/findings/${scanId}/${index}`)); setCommentInput(""); setNotice("Finding comment added.");
    } catch (error) { setNotice(error.message); }
    finally { setBusy(false); }
  }

  async function scanRegisteredProject(project) {
    setBusy(true); setNotice("");
    try {
      const result = await request(`/projects/${project.id}/scan`, { method: "POST" });
      setNotice(`Project scan ${result.status}: ${result.total_findings} findings recorded.`);
      await load();
    } catch (error) { setNotice(error.message); }
    finally { setBusy(false); }
  }

  async function inspectIncident(incident) {
    try { setSelectedIncident(await request(`/incidents/${incident.id}`)); }
    catch (error) { setNotice(error.message); }
  }

  async function inspectProject(project) {
    try { setSelectedProject(await request(`/projects/${project.id}`)); }
    catch (error) { setNotice(error.message); }
  }

  async function saveProjectEdit(event) {
    event.preventDefault();
    if (!selectedProject || !projectEdit) return;
    setBusy(true); setNotice("");
    try {
      const updated = await request(`/projects/${selectedProject.id}`, { method: "PATCH", body: JSON.stringify(projectEdit) });
      setSelectedProject(updated); setProjectEdit(null); setNotice("Project details saved."); await load();
    } catch (error) { setNotice(error.message); }
    finally { setBusy(false); }
  }

  async function inspectComparison(scan) {
    try { setComparison(await request(`/scans/${scan.id}/comparison`)); }
    catch (error) { setNotice(error.message); }
  }

  const recordsList = useMemo(() => {
    if (!records) return [];
    return records.projects || records.findings || records.scans || records.events || records.incidents || records.notifications || [];
  }, [records]);
  const visibleRecords = useMemo(() => {
    const query = listQuery.trim().toLowerCase();
    return recordsList.filter((item) => {
      if (section === "Projects") {
        const matchesQuery = !query || `${item.name || ""} ${item.project_path || ""} ${item.description || ""}`.toLowerCase().includes(query);
        const matchesState = !listFilter || (listFilter === "Scanned" ? Number(item.scan_count) > 0 : Number(item.scan_count) === 0);
        return matchesQuery && matchesState;
      }
      if (section === "Scans") {
        const matchesQuery = !query || String(item.project_path || "").toLowerCase().includes(query);
        return matchesQuery && (!listFilter || item.status === listFilter);
      }
      return true;
    });
  }, [listFilter, listQuery, recordsList, section]);

  async function markNotificationRead(notification) {
    setBusy(true); setNotice("");
    try {
      await request(`/notifications/${notification.id}/read`, { method: "PATCH" });
      setNotice("Notification marked as read.");
      await load();
      onNotificationsChange?.();
    } catch (error) { setNotice(error.message); }
    finally { setBusy(false); }
  }

  async function runIntegrationScan(event) {
    event.preventDefault(); setBusy(true); setNotice("");
    try {
      const result = await request(`/integrations/${integrationTool}/scan`, {
        method: "POST", body: JSON.stringify({ project_id: Number(integrationProjectId), timeout_seconds: 300 }),
      });
      setNotice(`${result.scanner} scan ${result.status}: ${result.total_findings} findings recorded.`);
      await load();
    } catch (error) { setNotice(error.message); }
    finally { setBusy(false); }
  }

  async function importSarif(event) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const file = formElement.elements.sarif.files?.[0];
    const projectId = formElement.elements.project.value;
    if (!file || !projectId) { setNotice("Choose a project and SARIF JSON file."); return; }
    if (file.size > 25 * 1024 * 1024) { setNotice("SARIF file exceeds the 25 MB import limit."); return; }
    setBusy(true); setNotice("");
    try {
      const sarif = JSON.parse(await file.text());
      const result = await request("/integrations/sarif/import", {
        method: "POST", body: JSON.stringify({ project_id: Number(projectId), sarif }),
      });
      formElement.reset();
      setNotice(`Imported ${result.total_findings} SARIF findings into scan ${result.scan_id}.`);
      await load();
    } catch (error) { setNotice(error instanceof SyntaxError ? "SARIF file is not valid JSON." : error.message); }
    finally { setBusy(false); }
  }

  return <>
    <div className="page-header module-header">
      <div><span className="section-label">SecurCode workspace</span><h1>{title}</h1><p>{description}</p></div>
      <button className="button button-secondary" onClick={load} disabled={status.loading}>Refresh data</button>
    </div>
    {notice && <div className="module-notice" role="status">{notice}</div>}

    {section === "Projects" && <>
      {canManage && <form className="module-form" onSubmit={submitProject}>
        <label>Project name<input required maxLength="120" value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} placeholder="Payments service" /></label>
        <label>Workspace path<input required maxLength="500" value={form.project_path} onChange={(event) => setForm({ ...form, project_path: event.target.value })} placeholder="backend" /></label>
        <label>Description<input maxLength="1000" value={form.description} onChange={(event) => setForm({ ...form, description: event.target.value })} placeholder="Optional project context" /></label>
        <label>Project owner<input maxLength="120" value={form.owner} onChange={(event) => setForm({ ...form, owner: event.target.value })} placeholder="Team or owner" /></label>
        <label>Repository URL<input type="url" maxLength="500" value={form.repository_url} onChange={(event) => setForm({ ...form, repository_url: event.target.value })} placeholder="https://github.com/org/repository" /></label>
        <span className="repository-note" role="note">Repository URLs are metadata only; remote repositories are not fetched or scanned.</span>
        <label>Default branch<input required maxLength="120" value={form.default_branch} onChange={(event) => setForm({ ...form, default_branch: event.target.value })} /></label>
        <button className="button button-primary" disabled={busy}>Register project</button>
      </form>}
      <div className="section-tools module-filter"><label htmlFor="project-search">Search projects</label><input id="project-search" value={listQuery} onChange={(event) => setListQuery(event.target.value)} placeholder="Name, path, or description" /><label htmlFor="project-scan-filter">Coverage</label><select id="project-scan-filter" value={listFilter} onChange={(event) => setListFilter(event.target.value)}><option value="">All projects</option><option>Scanned</option><option>Not scanned</option></select><span className="table-count">{visibleRecords.length} of {records?.total ?? "--"} projects</span></div>
      <TableState loading={status.loading} error={status.error} empty={records && visibleRecords.length === 0 ? { title: recordsList.length ? "No projects match these filters" : "No projects registered", detail: recordsList.length ? "Adjust the project search or coverage filter." : "Register an existing workspace directory to track its scan history." } : null} columns={["Project", "Workspace path", "Scans", "Findings", "Security status", "Last scan", "Actions"]}>
        {visibleRecords.map((project) => <tr key={project.id}><td><strong>{project.name}</strong><span className="table-subtext">{project.description || "No description"}</span></td><td><code>{project.project_path}</code></td><td>{project.scan_count}</td><td>{project.finding_count}</td><td><span className={`status-badge ${Number(project.finding_count) ? "status-partial" : "status-completed"}`}><span className="status-dot" />{Number(project.finding_count) ? "Findings detected" : Number(project.scan_count) ? "No findings" : "Not scanned"}</span></td><td>{project.last_scan_at || "No scans yet"}</td><td>{canScan && <button className="table-action" disabled={busy} onClick={() => scanRegisteredProject(project)}>Scan</button>}<button className="table-action" onClick={() => inspectProject(project)}>Details</button></td></tr>)}
      </TableState>
      {selectedProject && <section className="detail-panel"><div className="section-heading"><div><span className="section-label">Project overview</span><h2>{selectedProject.name}</h2></div><div>{canManage && <button className="text-button" onClick={() => setProjectEdit({ name: selectedProject.name, description: selectedProject.description || "", owner: selectedProject.owner || "", repository_url: selectedProject.repository_url || "", default_branch: selectedProject.default_branch || "main" })}>Edit details</button>}<button className="text-button" onClick={() => { setSelectedProject(null); setProjectEdit(null); }}>Close</button></div></div>{projectEdit ? <form className="module-form project-edit-form" onSubmit={saveProjectEdit}><label>Project name<input required maxLength="120" value={projectEdit.name} onChange={(event) => setProjectEdit({ ...projectEdit, name: event.target.value })} /></label><label>Description<input maxLength="1000" value={projectEdit.description} onChange={(event) => setProjectEdit({ ...projectEdit, description: event.target.value })} /></label><label>Owner<input maxLength="120" value={projectEdit.owner} onChange={(event) => setProjectEdit({ ...projectEdit, owner: event.target.value })} /></label><label>Repository URL<input type="url" maxLength="500" value={projectEdit.repository_url} onChange={(event) => setProjectEdit({ ...projectEdit, repository_url: event.target.value })} /></label><label>Default branch<input required maxLength="120" value={projectEdit.default_branch} onChange={(event) => setProjectEdit({ ...projectEdit, default_branch: event.target.value })} /></label><button className="button button-primary" disabled={busy}>Save project</button><button className="button button-secondary" type="button" onClick={() => setProjectEdit(null)}>Cancel</button></form> : <p>{selectedProject.description || "No description."}</p>}<dl><dt>Workspace path</dt><dd><code>{selectedProject.project_path}</code></dd><dt>Owner</dt><dd>{selectedProject.owner || "Unassigned"}</dd><dt>Repository</dt><dd>{selectedProject.repository_url || "Not linked"}</dd><dt>Default branch</dt><dd><code>{selectedProject.default_branch}</code></dd><dt>Recorded scans</dt><dd>{selectedProject.scan_count}</dd><dt>Stored findings</dt><dd>{selectedProject.finding_count}</dd><dt>Recent scans</dt><dd>{selectedProject.recent_scans.map((scan) => `${scan.id} · ${scan.status} · ${scan.created_at}`).join("; ") || "No scans yet."}</dd></dl></section>}
    </>}

    {section === "Scans" && <>
      {canScan && <form className="module-form scan-form-module" onSubmit={submitScan}>
        <label>Workspace-relative path<input required maxLength="500" value={form.project_path} onChange={(event) => setForm({ ...form, project_path: event.target.value })} placeholder="backend/app/api/docs/security-demo" /></label>
        <button className="button button-primary" disabled={busy}>{busy ? "Scanning…" : "Start scan"}</button>
      </form>}
      <div className="section-tools module-filter"><label htmlFor="scan-history-search">Project path</label><input id="scan-history-search" value={listQuery} onChange={(event) => setListQuery(event.target.value)} placeholder="Filter by workspace path" /><label htmlFor="scan-history-status">Status</label><select id="scan-history-status" value={listFilter} onChange={(event) => setListFilter(event.target.value)}><option value="">All statuses</option>{["completed", "partial", "failed"].map((item) => <option key={item} value={item}>{item}</option>)}</select><span className="table-count">{visibleRecords.length} of {records?.total ?? "--"} scans</span></div>
      <TableState loading={status.loading} error={status.error} empty={records && visibleRecords.length === 0 ? { title: recordsList.length ? "No scans match these filters" : "No scans recorded", detail: recordsList.length ? "Adjust the project path or status filter." : "Start a scan using a relative directory or supported source file inside the backend workspace." } : null} columns={["Status", "Project", "Findings", "Scanned", "Comparison"]}>
        {visibleRecords.map((scan) => <tr key={scan.id}><td><span className={`status-badge status-${scan.status}`}><span className="status-dot" />{scan.status}</span></td><td><code>{scan.project_path}</code></td><td>{scan.total_findings}</td><td>{scan.created_at}</td><td><button className="table-action" onClick={() => inspectComparison(scan)}>Compare</button></td></tr>)}
      </TableState>
      {comparison && <section className="detail-panel"><div className="section-heading"><div><span className="section-label">Scan comparison</span><h2>Scan {comparison.scan_id} vs {comparison.compared_to_scan_id ?? "no earlier scan"}</h2></div><button className="text-button" onClick={() => setComparison(null)}>Close</button></div><p>{comparison.comparison_note}</p><p className="comparison-summary">{comparison.added.length} newly detected · {comparison.no_longer_detected.length} no longer detected · {comparison.unchanged_count} unchanged</p></section>}
    </>}

    {section === "Vulnerabilities" && <>
      <div className="section-tools module-filter"><label htmlFor="finding-search">Search</label><input id="finding-search" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Rule, file, or description" /><label htmlFor="finding-status-filter">Lifecycle</label><select id="finding-status-filter" value={filter} onChange={(event) => setFilter(event.target.value)}><option value="">All statuses</option>{findingStatuses.map((item) => <option key={item}>{item}</option>)}</select><label htmlFor="finding-severity-filter">Severity</label><select id="finding-severity-filter" value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)}><option value="">All severities</option>{severities.map((item) => <option key={item}>{item}</option>)}</select><label htmlFor="finding-language-filter">Language</label><select id="finding-language-filter" value={languageFilter} onChange={(event) => setLanguageFilter(event.target.value)}><option value="">All languages</option>{["Python", "JavaScript", "TypeScript"].map((item) => <option key={item}>{item}</option>)}</select><span className="table-count">{records?.total ?? "--"} findings</span></div>
      <TableState loading={status.loading} error={status.error} empty={records && recordsList.length === 0 ? { title: "No findings to review", detail: "Run a scan on a supported source directory to populate vulnerability management." } : null} columns={["Severity", "Rule", "Project / file", "Line", "Status", "Assignee", "Review"]}>
        {recordsList.map((finding) => <tr key={`${finding.scan_id}:${finding.finding_index}`}><td><span className={`severity severity-${String(finding.severity || "unknown").toLowerCase()}`}>{finding.severity}</span></td><td><code>{finding.test_id}</code></td><td><span className="table-subtext">{finding.project_path}</span><code>{finding.filename}</code></td><td>{finding.line_number}</td><td><StatusSelect label="Finding status" value={finding.status} values={findingStatuses} disabled={!canManage || busy} onChange={(next) => changeFindingStatus(finding, next)} /></td><td>{finding.assignee || "Unassigned"}</td><td><button className="table-action" onClick={() => inspectFinding(finding)}>Evidence and history</button>{canManage && <button className="table-action" onClick={() => { const severityPriority = { CRITICAL: "Critical", HIGH: "High", MEDIUM: "Medium", LOW: "Low" }[String(finding.severity || "").toUpperCase()]; setForm({ ...form, title: `Review ${finding.test_id} in ${finding.project_path}`, description: "Investigate this detected source-code weakness; the finding is not evidence of a confirmed breach.", priority: severityPriority || form.priority, finding_ref: [finding.scan_id, finding.finding_index] }); onNavigate("Incidents"); }}>Create incident</button>}</td></tr>)}
      </TableState>
      {selected && <section className="detail-panel"><div className="section-heading"><div><span className="section-label">Finding detail</span><h2>{selected.test_id} · {selected.status}</h2></div><button className="text-button" onClick={() => setSelected(null)}>Close</button></div><p>{selected.description}</p><dl><dt>Evidence location</dt><dd><code>{selected.filename}:{selected.line_number}</code></dd><dt>Recommended remediation</dt><dd>{selected.remediation}</dd><dt>Confidence</dt><dd>{selected.confidence || "Not supplied by this rule"}</dd><dt>Assignee</dt><dd>{selected.assignee || "Unassigned"}</dd><dt>Status history</dt><dd>{selected.status_history?.length ? selected.status_history.map((entry) => `${entry.from_status} → ${entry.to_status} · ${entry.created_at}`).join("; ") : "No status changes recorded."}</dd><dt>Comments</dt><dd>{selected.comments?.length ? selected.comments.map((item) => `${item.actor}: ${item.comment} · ${item.created_at}`).join("; ") : "No comments yet."}</dd></dl>{canContribute && <><form className="module-form" onSubmit={updateAssignee}><label>Assignee<input maxLength="120" value={assigneeInput} onChange={(event) => setAssigneeInput(event.target.value)} placeholder="SecurCode username" /></label><p className="module-description">Enter an active account username; leave blank to unassign.</p>{assignmentError && <p className="api-alert" role="alert">{assignmentError}</p>}<button className="button button-secondary" disabled={assignmentSaving}>{assignmentSaving ? "Saving assignment…" : "Save assignment"}</button></form><form className="module-form" onSubmit={addComment}><label>Comment<textarea required maxLength="4000" value={commentInput} onChange={(event) => setCommentInput(event.target.value)} /></label><button className="button button-secondary" disabled={busy}>Add comment</button></form></>}</section>}
    </>}

    {section === "Incidents" && <>
      {canManage && <form className="module-form incident-form" onSubmit={createIncident}>
        <label>Incident title<input required maxLength="200" value={form.title} onChange={(event) => setForm({ ...form, title: event.target.value })} placeholder="Describe the response work" /></label>
        <label>Priority<select value={form.priority} onChange={(event) => setForm({ ...form, priority: event.target.value })}>{["Critical", "High", "Medium", "Low"].map((item) => <option key={item}>{item}</option>)}</select></label>
        <label>Description<input maxLength="5000" value={form.description} onChange={(event) => setForm({ ...form, description: event.target.value })} placeholder="Response context and next steps" /></label>
        {form.finding_ref && <span className="form-context">Linked finding {form.finding_ref[0]}:{form.finding_ref[1]}</span>}
        <button className="button button-primary" disabled={busy}>Create incident</button>
      </form>}
      <div className="section-tools module-filter"><label htmlFor="incident-search">Search</label><input id="incident-search" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Incident title or description" /><label htmlFor="incident-status-filter">Status</label><select id="incident-status-filter" value={filter} onChange={(event) => setFilter(event.target.value)}><option value="">All statuses</option>{incidentStatuses.map((item) => <option key={item}>{item}</option>)}</select></div>
      <TableState loading={status.loading} error={status.error} empty={records && recordsList.length === 0 ? { title: "No incidents recorded", detail: "Create an incident manually or start one from a vulnerability finding." } : null} columns={["Incident", "Priority", "Severity", "Status", "Owner", "Findings", "Updated", "Details"]}>
        {recordsList.map((incident) => <tr key={incident.id}><td><strong>{incident.title}</strong><span className="table-subtext">{incident.description || "No description"}</span></td><td>{incident.priority}</td><td>{incident.severity}</td><td><StatusSelect label="Incident status" value={incident.status} values={incidentStatuses} disabled={!canManage || busy} onChange={(next) => changeIncidentStatus(incident, next)} /></td><td>{incident.owner || "Unassigned"}</td><td>{incident.finding_count}</td><td>{incident.updated_at}</td><td><button className="table-action" onClick={() => inspectIncident(incident)}>Open</button></td></tr>)}
      </TableState>
      {selectedIncident && <section className="detail-panel"><div className="section-heading"><div><span className="section-label">Incident detail</span><h2>{selectedIncident.title}</h2></div><button className="text-button" onClick={() => setSelectedIncident(null)}>Close</button></div><p>{selectedIncident.description || "No description."}</p><dl><dt>Severity / priority</dt><dd>{selectedIncident.severity} / {selectedIncident.priority}</dd><dt>Owner</dt><dd>{selectedIncident.owner || "Unassigned"}</dd><dt>Resolution notes</dt><dd>{selectedIncident.resolution_notes || "None recorded."}</dd><dt>Related findings</dt><dd>{selectedIncident.findings.map((finding) => `${finding.test_id} · ${finding.filename}:${finding.line_number} · ${finding.status}`).join("; ") || "No related findings."}</dd><dt>Activity</dt><dd>{selectedIncident.activity.map((entry) => `${entry.action} · ${entry.actor} · ${entry.created_at}`).join("; ") || "No activity recorded."}</dd></dl></section>}
    </>}

    {section === "Audit Logs" && <><div className="section-tools module-filter"><label htmlFor="audit-action-filter">Filter by exact action</label><input id="audit-action-filter" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="finding.status_changed" /></div><TableState loading={status.loading} error={status.error} empty={records && recordsList.length === 0 ? { title: "No audit events yet", detail: "Scan and workflow changes will appear here with an actor and safe event metadata." } : null} columns={["Time", "Actor", "Action", "Resource", "Outcome", "Metadata"]}>
      {recordsList.map((event) => <tr key={event.id}><td>{event.created_at}</td><td>{event.actor}</td><td><code>{event.action}</code></td><td>{event.resource_type} · {event.resource_id}</td><td>{event.outcome}</td><td><code className="metadata-value">{JSON.stringify(event.metadata)}</code></td></tr>)}
    </TableState></>}

    {section === "Notifications" && <>
      <div className="notification-summary"><strong>{records?.unread_count || 0} unread</strong><span>Notifications are generated from persisted local scan and workflow events. Read state is shared by the trusted local operator.</span></div>
      <TableState loading={status.loading} error={status.error} empty={records && recordsList.length === 0 ? { title: "No notifications", detail: "Scan completion, critical findings, assignments, and incident creation will appear here." } : null} columns={["State", "Event", "Message", "Created", "Action"]}>
        {recordsList.map((item) => <tr key={item.id}><td>{item.read_at ? "Read" : <strong>Unread</strong>}</td><td><span className="status-badge">{item.category.replaceAll("_", " ")}</span></td><td><strong>{item.title}</strong><span className="table-subtext">{item.message}</span></td><td>{item.created_at}</td><td><button className="table-action" onClick={() => onNavigate(item.href.split("?")[0].slice(1))}>Open</button>{!item.read_at && !readOnly && role !== "read_only" && <button className="table-action" disabled={busy} onClick={() => markNotificationRead(item)}>Mark read</button>}</td></tr>)}
      </TableState>
    </>}

    {section === "Integrations" && <>
      {status.loading ? <div className="module-message" role="status">Checking optional scanners…</div> : status.error ? <div className="api-alert" role="alert"><div><strong>Integration status unavailable</strong><span>{status.error}</span></div></div> : <>
        <section className="integration-grid" aria-label="Optional scanner availability">
          {Object.entries(integrationData?.integrations || {}).map(([tool, item]) => <article className="integration-card" key={tool}><div><span className={`status-badge ${item.available ? "status-completed" : "status-partial"}`}><span className="status-dot" />{item.available ? "Available" : "Not installed"}</span><h2>{tool}</h2><p>{item.version || (item.available ? "Version could not be read" : "Install explicitly and make it available on PATH.")}</p></div></article>)}
        </section>
        <section className="detail-panel"><span className="section-label">Optional scanners</span><h2>Run a scanner on a registered project</h2><p>Scanners run only when selected. Each call has a timeout and output cap. Semgrep requires a local rules file configured with SECURCODE_SEMGREP_CONFIG; SecurCode does not download rules.</p>
          <form className="module-form integration-form" onSubmit={runIntegrationScan}><label>Scanner<select value={integrationTool} onChange={(event) => setIntegrationTool(event.target.value)}><option value="bandit">Bandit</option><option value="semgrep">Semgrep</option><option value="gitleaks">Gitleaks</option><option value="trivy">Trivy</option></select></label><label>Project<select required value={integrationProjectId} onChange={(event) => setIntegrationProjectId(event.target.value)}><option value="">Choose a project</option>{(integrationData?.projects || []).map((project) => <option key={project.id} value={project.id}>{project.name} · {project.project_path}</option>)}</select></label><button className="button button-primary" disabled={busy || !canScan || !integrationProjectId}>{busy ? "Running…" : "Run scanner"}</button></form>
        </section>
        <section className="detail-panel"><span className="section-label">CodeQL and other SARIF producers</span><h2>Import SARIF 2.x results</h2><p>Imported paths are normalized or redacted; finding attribution and rule metadata are kept in scan history.</p><form className="module-form integration-form" onSubmit={importSarif}><label>Project<select name="project" required defaultValue=""><option value="">Choose a project</option>{(integrationData?.projects || []).map((project) => <option key={project.id} value={project.id}>{project.name} · {project.project_path}</option>)}</select></label><label>SARIF JSON<input name="sarif" type="file" accept="application/json,.sarif" required /></label><button className="button button-secondary" disabled={busy || !canManage}>{busy ? "Importing…" : "Import SARIF"}</button></form></section>
      </>}
    </>}

    {section === "Reports" && <>
      {status.loading ? <div className="module-message" role="status">Loading report data…</div> : status.error ? <div className="api-alert" role="alert"><div><strong>Report data unavailable</strong><span>{status.error}</span></div></div> : dashboard && <>
        <div className="metric-grid report-metrics"><div className="metric"><span>Total scans</span><strong>{dashboard.total_scans}</strong></div><div className="metric"><span>Total findings</span><strong>{dashboard.total_findings}</strong></div><div className="metric"><span>Projects</span><strong>{dashboard.projects_count}</strong></div><div className="metric"><span>High / critical</span><strong>{dashboard.high_severity_findings}</strong></div></div>
        <div className="report-actions"><div><h2>Finding export</h2><p>CSV includes finding evidence, project-relative paths, and remediation status. Spreadsheet formula prefixes are escaped.</p></div><button className="button button-primary" onClick={downloadFindingReport}>Download findings CSV</button></div>
        <div className="table-section"><div className="section-heading"><div><h2>Available reports</h2><p>Generation state reflects live API data and supported export formats.</p></div></div><TableState loading={false} error="" columns={["Report", "Category", "Status", "Format", "Action"]}><tr><td><strong>Workspace findings</strong><span className="table-subtext">Current finding evidence and remediation state</span></td><td>Vulnerability inventory</td><td><span className="status-badge status-completed"><span className="status-dot" />Ready</span></td><td>CSV</td><td><button className="table-action" onClick={downloadFindingReport}>Download CSV</button></td></tr><tr><td><strong>Workspace posture</strong><span className="table-subtext">Current scan, finding, and project summary</span></td><td>Security posture</td><td><span className="status-badge status-running"><span className="status-dot" />Live data</span></td><td>On screen</td><td><span className="muted-value">No export endpoint</span></td></tr></TableState></div>
        <div className="table-section"><h2>Scan trend</h2><p className="module-description">Daily scan volume and finding totals from recorded scans.</p><TableState loading={false} error="" empty={dashboard.trends.length === 0 ? { title: "No trend data", detail: "Run scans to build a time series from real scan history." } : null} columns={["Date", "Scans", "Findings"]}>{dashboard.trends.map((item) => <tr key={item.date}><td>{item.date}</td><td>{item.scans}</td><td>{item.findings}</td></tr>)}</TableState></div>
      </>}
    </>}

    {section === "Configuration" && <section className="settings-panel"><span className="section-label">Instance configuration</span><h2>Operating boundaries</h2><dl><dt>API endpoint</dt><dd><code>{import.meta.env.VITE_API_BASE_URL || (import.meta.env.DEV ? "http://127.0.0.1:8000" : "same origin")}</code></dd><dt>Write access</dt><dd>{readOnly ? "Disabled by public demo policy" : `Authenticated session · ${role.replaceAll("_", " ")}`}</dd><dt>Filesystem scope</dt><dd>Relative paths inside the backend workspace; symbolic link targets are rejected.</dd><dt>Scan limits</dt><dd>Files, directory depth, elapsed time, per-file size, and total bytes use SECURCODE_MAX_SCAN_FILES, SECURCODE_MAX_SCAN_DEPTH, SECURCODE_MAX_SCAN_SECONDS, SECURCODE_MAX_SOURCE_FILE_BYTES, and SECURCODE_MAX_SCAN_BYTES.</dd><dt>Scanner coverage</dt><dd>Python AST plus bounded intra-file dataflow; JavaScript / TypeScript lexical checks. Findings require engineering review.</dd></dl><a href={`${import.meta.env.DEV && !CONFIGURED_API_BASE_URL ? "/api" : API_BASE_URL}/docs`} target="_blank" rel="noreferrer">Open interactive API documentation</a></section>}
    {section === "Settings" && <><section className="settings-panel"><span className="section-label">Workspace preferences</span><h2>Console settings</h2><p>Color theme is available in the top navigation and is saved in this browser. Workspace preferences are currently local to this console.</p><dl><dt>Theme</dt><dd>Light by default, with an optional dark theme.</dd><dt>API connection</dt><dd>Configured by VITE_API_BASE_URL or the development proxy.</dd></dl></section>{!readOnly && <form className="module-form" onSubmit={changePassword}><span className="section-label">Account security</span><label>Current password<input required minLength="12" type="password" autoComplete="current-password" value={passwordForm.current_password} onChange={(event) => setPasswordForm({ ...passwordForm, current_password: event.target.value })} /></label><label>New password<input required minLength="12" type="password" autoComplete="new-password" value={passwordForm.new_password} onChange={(event) => setPasswordForm({ ...passwordForm, new_password: event.target.value })} /></label><button className="button button-primary" disabled={busy}>Change password</button></form>}</>}
    {section === "Access & Permissions" && <><section className="settings-panel"><span className="section-label">Access control</span><h2>Role-based access</h2><p>API requests require an authenticated session outside the public read-only demo. Role checks are enforced by the backend.</p><dl><dt>Signed-in identity</dt><dd>{role.replaceAll("_", " ")}</dd><dt>Administrator</dt><dd>Manage users and all platform workflows.</dd><dt>Security analyst</dt><dd>Manage projects, findings, incidents, and integrations.</dd><dt>Developer</dt><dd>Run scans and collaborate on finding comments and assignments.</dd><dt>Read only</dt><dd>View stored security data without changing it.</dd><dt>Project-level access</dt><dd>Not implemented; permissions apply across this local instance.</dd></dl></section>{role === "administrator" && <><form className="module-form" onSubmit={submitUser}><label>Username<input required minLength="3" maxLength="120" value={userForm.username} onChange={(event) => setUserForm({ ...userForm, username: event.target.value })} /></label><label>Temporary password<input required minLength="12" type="password" autoComplete="new-password" value={userForm.password} onChange={(event) => setUserForm({ ...userForm, password: event.target.value })} /></label><label>Role<select value={userForm.role} onChange={(event) => setUserForm({ ...userForm, role: event.target.value })}><option value="security_analyst">Security analyst</option><option value="developer">Developer</option><option value="read_only">Read only</option><option value="administrator">Administrator</option></select></label><button className="button button-primary" disabled={busy}>Create account</button></form><TableState loading={status.loading} error={status.error} columns={["Username", "Role", "Status", "Created", "Action"]}>{users.map((user) => <tr key={user.id}><td>{user.username}</td><td><select aria-label={`Role for ${user.username}`} value={user.role} disabled={busy || user.id === userId} onChange={(event) => changeUserRole(user, event.target.value)}><option value="administrator">Administrator</option><option value="security_analyst">Security analyst</option><option value="developer">Developer</option><option value="read_only">Read only</option></select></td><td>{user.disabled ? "Disabled" : "Active"}</td><td>{user.created_at}</td><td><button className="table-action" disabled={busy || user.id === userId} onClick={() => toggleUser(user)}>{user.disabled ? "Enable" : "Disable"}</button></td></tr>)}</TableState></>}</>}
  </>;
}

const CONFIGURED_API_BASE_URL = import.meta.env.VITE_API_BASE_URL;
const API_BASE_URL = (CONFIGURED_API_BASE_URL || (import.meta.env.DEV ? "http://127.0.0.1:8000" : "")).replace(/\/$/, "");
