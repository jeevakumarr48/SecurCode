import { useEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import "./styles.css";

const CONFIGURED_API_BASE_URL = import.meta.env.VITE_API_BASE_URL;
const API_BASE_URL = (CONFIGURED_API_BASE_URL || "http://127.0.0.1:8000").replace(/\/$/, "");
const REQUEST_BASE_URL = import.meta.env.DEV && !CONFIGURED_API_BASE_URL ? "/api" : API_BASE_URL;

const navigation = [
  { label: "Overview", icon: "grid" },
  { label: "Security Scans", icon: "scan" },
  { label: "Findings", icon: "finding" },
  { label: "Scan History", icon: "history" },
  { label: "Settings", icon: "settings" },
];

function Icon({ name, size = 18 }) {
  const paths = {
    grid: <><rect x="3" y="3" width="7" height="7" rx="1" /><rect x="14" y="3" width="7" height="7" rx="1" /><rect x="3" y="14" width="7" height="7" rx="1" /><rect x="14" y="14" width="7" height="7" rx="1" /></>,
    scan: <><path d="M7 3H4a1 1 0 0 0-1 1v3" /><path d="M17 3h3a1 1 0 0 1 1 1v3" /><path d="M7 21H4a1 1 0 0 1-1-1v-3" /><path d="M17 21h3a1 1 0 0 0 1-1v-3" /><path d="M8 12h8" /><path d="M12 8v8" /></>,
    finding: <><path d="M12 3 21 7.8v8.4L12 21l-9-4.8V7.8L12 3Z" /><path d="M12 8v4" /><path d="M12 16h.01" /></>,
    history: <><path d="M3 12a9 9 0 1 0 3-6.7" /><path d="M3 4v5h5" /><path d="M12 7v5l3 2" /></>,
    settings: <><path d="M12 15.5a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7Z" /><path d="m19.4 15 .1.1a2 2 0 1 1-2.8 2.8l-.1-.1a2 2 0 0 0-3.4 1.4v.3a2 2 0 1 1-4 0v-.2A2 2 0 0 0 5.8 18l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1A2 2 0 0 0 1.6 12a2 2 0 1 1 4 0 2 2 0 0 0 3.4-1.4v-.3a2 2 0 1 1 4 0v.2A2 2 0 0 0 16.4 12l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1A2 2 0 0 0 19.4 15Z" /></>,
    menu: <><path d="M4 6h16" /><path d="M4 12h16" /><path d="M4 18h16" /></>,
    close: <><path d="m6 6 12 12" /><path d="m18 6-12 12" /></>,
    arrow: <><path d="M5 12h14" /><path d="m13 6 6 6-6 6" /></>,
    refresh: <><path d="M20 11a8.1 8.1 0 0 0-14.8-3L3 11" /><path d="M3 5v6h6" /><path d="M4 13a8.1 8.1 0 0 0 14.8 3L21 13" /><path d="M21 19v-6h-6" /></>,
    shield: <><path d="M12 3 20 6v5.3c0 4.6-3.1 8-8 9.7-4.9-1.7-8-5.1-8-9.7V6l8-3Z" /><path d="m8.5 12 2.2 2.2 4.8-4.8" /></>,
  };

  return (
    <svg aria-hidden="true" className="icon" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
      {paths[name]}
    </svg>
  );
}

async function request(path, options = {}) {
  const response = await fetch(`${REQUEST_BASE_URL}${path}`, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });

  if (!response.ok) {
    let message = `Request failed with status ${response.status}.`;
    try {
      const payload = await response.json();
      message = payload.detail || message;
    } catch {
      // Keep the useful HTTP error when the API did not return JSON.
    }
    throw new Error(message);
  }

  return response.json();
}

function formatNumber(value) {
  return new Intl.NumberFormat("en-US").format(Number(value || 0));
}

function formatTimestamp(value) {
  if (!value) return "Not available";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "numeric",
    minute: "2-digit",
  }).format(date);
}

function shortPath(value) {
  if (!value) return "Unknown project";
  const normalized = value.replaceAll("\\", "/");
  const parts = normalized.split("/").filter(Boolean);
  return parts.length > 2 ? `.../${parts.slice(-2).join("/")}` : normalized;
}

function severityClass(severity) {
  return `severity severity-${String(severity || "unknown").toLowerCase()}`;
}

function normalizedSeverity(severity) {
  return String(severity || "unknown").toUpperCase();
}

function StatusBadge({ status }) {
  const normalized = String(status || "unknown").toLowerCase();
  return <span className={`status-badge status-${normalized}`}><span className="status-dot" />{normalized}</span>;
}

function Metric({ label, value, icon, tone = "neutral", loading }) {
  return (
    <div className={`metric metric-${tone}`}>
      <div className="metric-heading"><span>{label}</span><span className="metric-icon"><Icon name={icon} size={16} /></span></div>
      {loading ? <div className="skeleton metric-skeleton" /> : <strong>{value == null ? "--" : formatNumber(value)}</strong>}
    </div>
  );
}

function EmptyTable({ children, colSpan }) {
  return <tr><td className="empty-cell" colSpan={colSpan}>{children}</td></tr>;
}

function App() {
  const [activeNav, setActiveNav] = useState("Overview");
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [data, setData] = useState({ status: null, stats: null, history: null });
  const [watcherData, setWatcherData] = useState({ status: null, findings: null, error: "" });
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [connectionError, setConnectionError] = useState("");
  const [scanPath, setScanPath] = useState("");
  const [scanState, setScanState] = useState("idle");
  const [scanMessage, setScanMessage] = useState("");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [languageFilter, setLanguageFilter] = useState("ALL");
  const [selectedScanId, setSelectedScanId] = useState("ALL");
  const inputRef = useRef(null);
  const findingsSectionRef = useRef(null);

  async function loadDashboard(isRefresh = false) {
    if (isRefresh) setRefreshing(true);
    else setLoading(true);

    const results = await Promise.allSettled([
      request("/status"),
      request("/stats"),
      request("/history?limit=20"),
    ]);
    const [status, stats, history] = results;
    const nextData = {
      status: status.status === "fulfilled" ? status.value : null,
      stats: stats.status === "fulfilled" ? stats.value : null,
      history: history.status === "fulfilled" ? history.value : null,
    };
    setData(nextData);
    const failedRequests = [
      ["status", status],
      ["stats", stats],
      ["history", history],
    ].filter(([, result]) => result.status === "rejected");
    setConnectionError(failedRequests.length > 0 ? failedRequests.map(([name, result]) => `${name}: ${result.reason.message}`).join(" ") : "");
    setLoading(false);
    setRefreshing(false);
    return nextData;
  }

  useEffect(() => {
    loadDashboard();
  }, []);

  useEffect(() => {
    let active = true;
    let requestPending = false;

    async function loadWatcher() {
      if (requestPending) return;
      requestPending = true;
      try {
        const [status, findings] = await Promise.all([
          request("/watcher/status"),
          request("/watcher/findings"),
        ]);
        if (active) setWatcherData({ status, findings, error: "" });
      } catch (error) {
        if (active) setWatcherData((current) => ({ ...current, error: error.message }));
      } finally {
        requestPending = false;
      }
    }

    loadWatcher();
    const interval = window.setInterval(loadWatcher, 2000);
    return () => {
      active = false;
      window.clearInterval(interval);
    };
  }, []);

  async function handleScan(event) {
    event.preventDefault();
    const projectPath = scanPath.trim();
    if (!projectPath) {
      setScanState("error");
      setScanMessage("Enter a relative project path before starting the scan.");
      inputRef.current?.focus();
      return;
    }

    setScanState("loading");
    setScanMessage("Scanning project files. This may take a moment.");
    try {
      const result = await request("/scan", {
        method: "POST",
        body: JSON.stringify({ project_path: projectPath }),
      });
      const refreshedData = await loadDashboard(true);
      const latestScan = refreshedData.history?.scans?.[0];
      if (latestScan) {
        setSelectedScanId(String(latestScan.id));
      }
      setSeverityFilter("ALL");
      setLanguageFilter("ALL");
      setScanState("success");
      setScanMessage(`Scan completed with ${formatNumber(result.total_findings)} finding${result.total_findings === 1 ? "" : "s"}.`);
    } catch (error) {
      setScanState("error");
      setScanMessage(error.message);
    }
  }

  const scans = data.history?.scans || [];
  const allFindings = scans.flatMap((scan) => (scan.findings || []).map((finding) => ({ ...finding, scan_id: scan.id, project_path: scan.project_path, scan_created_at: scan.created_at })));
  const selectedScan = selectedScanId === "ALL" ? null : scans.find((scan) => String(scan.id) === selectedScanId);
  const selectedScanValue = selectedScan ? selectedScanId : "ALL";
  const scopedFindings = selectedScan
    ? allFindings.filter((finding) => String(finding.scan_id) === selectedScanId)
    : allFindings;
  const languageFilterSupported = scopedFindings.some((finding) => finding.language);
  const languages = [...new Set(scopedFindings.filter((finding) => finding.language).map((finding) => finding.language))].sort();
  const findings = scopedFindings.filter((finding) => {
    const severityMatches = severityFilter === "ALL" || normalizedSeverity(finding.severity) === severityFilter;
    const languageMatches = languageFilter === "ALL" || (finding.language || "Unknown") === languageFilter;
    return severityMatches && languageMatches;
  });
  const connectionHealthy = data.status?.status === "healthy";

  function chooseNav(label) {
    setActiveNav(label);
    setMobileNavOpen(false);
    if (label === "Security Scans") {
      inputRef.current?.focus();
    }
  }

  function selectScan(scanId) {
    setSelectedScanId(scanId);
    setSeverityFilter("ALL");
    setLanguageFilter("ALL");
    findingsSectionRef.current?.scrollIntoView({ block: "start" });
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="topbar-brand"><span className="brand-mark"><Icon name="shield" size={20} /></span><span>SecurCode</span></div>
        <div className="breadcrumb" aria-label="Breadcrumb"><span>Security</span><span className="breadcrumb-separator">/</span><strong>{activeNav}</strong></div>
        <div className="topbar-actions">
          <div className={`connection-state ${connectionHealthy ? "is-healthy" : "is-offline"}`} title={connectionError || (connectionHealthy ? "API connection healthy" : "Checking API connection")}><span className="connection-dot" /> <span>{connectionHealthy ? "API connected" : loading ? "Connecting" : "API unavailable"}</span></div>
          <button className="icon-button mobile-menu-button" onClick={() => setMobileNavOpen((open) => !open)} aria-label={mobileNavOpen ? "Close navigation" : "Open navigation"}><Icon name={mobileNavOpen ? "close" : "menu"} /></button>
        </div>
      </header>

      <div className="workspace">
        <aside className={`sidebar ${mobileNavOpen ? "sidebar-open" : ""}`}>
          <div className="sidebar-heading">Workspace</div>
          <nav aria-label="Primary navigation">
            {navigation.map((item) => (
              <button key={item.label} className={`nav-item ${activeNav === item.label ? "nav-item-active" : ""}`} onClick={() => chooseNav(item.label)}><Icon name={item.icon} size={17} /><span>{item.label}</span></button>
            ))}
          </nav>
          <div className="sidebar-footer"><span className="sidebar-footer-label">API endpoint</span><code>{API_BASE_URL.replace(/^https?:\/\//, "")}</code></div>
        </aside>

        <main className="main-content">
          <div className="page-header">
            <div><h1>Security Overview</h1><p>Review current scan coverage and resolve findings across your workspace.</p></div>
            <button className="button button-primary" onClick={() => inputRef.current?.focus()}><Icon name="scan" size={16} />Run new scan</button>
          </div>

          <section className="scan-action" aria-labelledby="scan-action-title">
            <div className="scan-action-copy"><span className="section-label">Scan workspace</span><h2 id="scan-action-title">Start a security scan</h2><p>Use a relative directory path inside the backend workspace.</p></div>
            <form className="scan-form" onSubmit={handleScan}>
              <label className="sr-only" htmlFor="project-path">Project path</label>
              <input ref={inputRef} id="project-path" value={scanPath} onChange={(event) => { setScanPath(event.target.value); if (scanState !== "idle") setScanState("idle"); }} placeholder="Project path, e.g. backend" disabled={scanState === "loading"} />
              <button className="button button-primary" type="submit" disabled={scanState === "loading"}>{scanState === "loading" ? <><span className="button-spinner" />Scanning</> : <>Scan project <Icon name="arrow" size={15} /></>}</button>
            </form>
            {scanState !== "idle" && <div className={`scan-feedback feedback-${scanState}`} role={scanState === "error" ? "alert" : "status"}><span className="feedback-icon">{scanState === "success" ? "✓" : scanState === "error" ? "!" : "·"}</span>{scanMessage}</div>}
          </section>

          <section className="table-section" aria-labelledby="watcher-title">
            <div className="section-heading">
              <div><h2 id="watcher-title">Live file watcher</h2><p>Latest findings from a changed source file in the watched demo directory.</p></div>
              <StatusBadge status={watcherData.status ? (watcherData.status.running ? "running" : "stopped") : watcherData.error ? "unavailable" : "connecting"} />
            </div>
            {watcherData.error ? <div className="api-alert" role="alert"><div><strong>Watcher data is unavailable</strong><span>{watcherData.error}</span></div></div> : <>
              <div className="findings-context"><span>Last file</span><strong title={watcherData.findings?.last_file || ""}>{watcherData.findings?.last_file ? shortPath(watcherData.findings.last_file) : "No file changes detected yet"}</strong><span>{formatNumber(watcherData.findings?.total_findings)} findings</span></div>
              <div className="table-wrap"><table><thead><tr><th>Severity</th><th>Rule ID</th><th>Line</th><th>Description</th></tr></thead><tbody>{!watcherData.findings ? <EmptyTable colSpan="4">Waiting for watcher results.</EmptyTable> : watcherData.findings.findings.length === 0 ? <EmptyTable colSpan="4">The latest changed file has no findings.</EmptyTable> : watcherData.findings.findings.map((finding, index) => <tr key={`${finding.test_id}-${finding.line_number}-${index}`}><td><span className={severityClass(finding.severity)}>{finding.severity || "Unknown"}</span></td><td><code className="rule-id">{finding.test_id || "-"}</code></td><td className="numeric-value">{finding.line_number ?? "-"}</td><td><span className="description-value">{finding.description || "No description provided."}</span></td></tr>)}</tbody></table></div>
            </>}
          </section>

          {connectionError && <div className="api-alert" role="alert"><div><strong>{data.status ? "Some dashboard data is unavailable" : "Unable to reach the SecurCode API"}</strong><span>{connectionError} Check that the backend is running at {API_BASE_URL}.</span></div><button className="button button-secondary" onClick={() => loadDashboard(true)} disabled={refreshing}><Icon name="refresh" size={15} />Retry</button></div>}

          <section className="metrics-section" aria-labelledby="metrics-title">
            <div className="section-heading"><h2 id="metrics-title">Environment summary</h2><button className="text-button" onClick={() => loadDashboard(true)} disabled={refreshing}><Icon name="refresh" size={14} />{refreshing ? "Refreshing" : "Refresh data"}</button></div>
            <div className="metric-grid"><Metric label="Total scans" value={data.stats?.total_scans} icon="scan" loading={loading} /><Metric label="Total findings" value={data.stats?.total_findings} icon="finding" loading={loading} tone="amber" /><Metric label="High-severity findings" value={data.stats?.high_severity_findings} icon="finding" loading={loading} tone="red" /></div>
          </section>

          <section className="table-section" aria-labelledby="recent-scans-title">
            <div className="section-heading"><div><h2 id="recent-scans-title">Recent scans</h2><p>Most recent project activity from the scan history.</p></div><span className="table-count">{data.history ? `${formatNumber(data.history.total)} total` : "--"}</span></div>
            <div className="table-wrap"><table><thead><tr><th>Status</th><th>Project path</th><th>Findings</th><th>Scanned</th><th>Inspect</th></tr></thead><tbody>{loading ? <><tr><td colSpan="5"><div className="table-skeleton" /></td></tr><tr><td colSpan="5"><div className="table-skeleton short" /></td></tr></> : !data.history ? <EmptyTable colSpan="5">Scan history could not be loaded. Retry the API request to view recorded activity.</EmptyTable> : scans.length === 0 ? <EmptyTable colSpan="5">No scans have been recorded yet. Start a scan above to populate this history.</EmptyTable> : scans.map((scan) => <tr key={scan.id}><td><StatusBadge status={scan.status} /></td><td><span className="path-value" title={scan.project_path}>{shortPath(scan.project_path)}</span></td><td className="numeric-value">{formatNumber(scan.total_findings)}</td><td className="muted-value">{formatTimestamp(scan.created_at)}</td><td><button className="table-action" type="button" onClick={() => selectScan(String(scan.id))}>View findings <Icon name="arrow" size={13} /></button></td></tr>)}</tbody></table></div>
           </section>

          <section ref={findingsSectionRef} className="table-section findings-section" aria-labelledby="findings-title">
            <div className="section-heading"><div><h2 id="findings-title">Findings Explorer</h2><p>Inspect stored findings from the loaded scan history.</p></div><div className="section-tools"><label className="filter-label" htmlFor="scan-filter">Scan</label><select id="scan-filter" value={selectedScanValue} onChange={(event) => selectScan(event.target.value)} disabled={!data.history || loading}><option value="ALL">All loaded scans</option>{scans.map((scan) => <option key={scan.id} value={scan.id}>{shortPath(scan.project_path)} · {formatTimestamp(scan.created_at)}</option>)}</select><label className="filter-label" htmlFor="severity-filter">Severity</label><select id="severity-filter" value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)} disabled={!data.history || loading}><option value="ALL">All severities</option><option value="HIGH">High</option><option value="CRITICAL">Critical</option><option value="MEDIUM">Medium</option><option value="LOW">Low</option></select>{languageFilterSupported && <><label className="filter-label" htmlFor="language-filter">Language</label><select id="language-filter" value={languageFilter} onChange={(event) => setLanguageFilter(event.target.value)} disabled={!data.history || loading}><option value="ALL">All languages</option>{languages.map((language) => <option key={language} value={language}>{language}</option>)}</select></>}<span className="table-count">{data.history ? `${formatNumber(findings.length)} of ${formatNumber(scopedFindings.length)}` : "--"}</span></div></div>
            {selectedScan && <div className="findings-context"><span>Selected historical scan</span><strong title={selectedScan.project_path}>{shortPath(selectedScan.project_path)}</strong><span>{formatTimestamp(selectedScan.created_at)} · {formatNumber(selectedScan.total_findings)} stored findings</span></div>}
            <div className="table-wrap"><table className="findings-table"><thead><tr><th>Severity</th><th>Language</th><th>Rule ID</th><th>File</th><th>Line</th><th>Confidence</th><th>Description</th></tr></thead><tbody>{loading ? <><tr><td colSpan="7"><div className="table-skeleton" /></td></tr><tr><td colSpan="7"><div className="table-skeleton short" /></td></tr></> : !data.history ? <EmptyTable colSpan="7">Finding data could not be loaded because scan history is unavailable.</EmptyTable> : findings.length === 0 ? <EmptyTable colSpan="7">{selectedScan ? "No findings are stored for this scan or the filters match no findings." : "No findings match the selected filters."}</EmptyTable> : findings.map((finding, index) => <tr key={`${finding.test_id}-${finding.filename}-${finding.line_number}-${index}`}><td><span className={severityClass(finding.severity)}>{finding.severity || "Unknown"}</span></td><td><span className="language-value">{finding.language || "Unknown"}</span></td><td><code className="rule-id">{finding.test_id || "-"}</code></td><td><span className="file-value" title={finding.filename}>{shortPath(finding.filename)}</span></td><td className="numeric-value">{finding.line_number ?? "-"}</td><td><span className="confidence-value">{finding.confidence || "Unknown"}</span></td><td><span className="description-value">{finding.description || "No description provided."}</span></td></tr>)}</tbody></table></div>
          </section>

          <footer className="content-footer"><span>SecurCode Security Scanner</span><span>API: {API_BASE_URL}</span></footer>
        </main>
      </div>
    </div>
  );
}

createRoot(document.getElementById("root")).render(<App />);
