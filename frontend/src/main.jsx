import { useEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { refreshHistoryAfterFailedScan } from "./scanHistoryRefresh.js";
import PlatformPage from "./platformPages.jsx";
import "./styles.css";

const CONFIGURED_API_BASE_URL = import.meta.env.VITE_API_BASE_URL;
const API_BASE_URL = (CONFIGURED_API_BASE_URL || (import.meta.env.DEV ? "http://127.0.0.1:8000" : "")).replace(/\/$/, "");
const REQUEST_BASE_URL = import.meta.env.DEV && !CONFIGURED_API_BASE_URL ? "/api" : API_BASE_URL;
const severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
let accessToken = "";

const navigation = [
  { group: "Security", label: "Overview", icon: "grid" },
  { group: "Security", label: "Projects", icon: "project" },
  { group: "Security", label: "Scans", icon: "scan" },
  { group: "Security", label: "Vulnerabilities", icon: "finding" },
  { group: "Security", label: "Incidents", icon: "incident" },
  { group: "Security", label: "Notifications", icon: "bell" },
  { group: "Governance", label: "Audit Logs", icon: "history" },
  { group: "Governance", label: "Reports", icon: "report" },
  { group: "Governance", label: "Integrations", icon: "settings" },
  { group: "Administration", label: "Configuration", icon: "settings" },
  { group: "Administration", label: "Settings", icon: "settings" },
  { group: "Administration", label: "Access & Permissions", icon: "users" },
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
    project: <><rect x="3" y="5" width="18" height="15" rx="2" /><path d="M3 9h18M8 5V3h8v2" /></>,
    incident: <><path d="M12 3 21 7.8v8.4L12 21l-9-4.8V7.8L12 3Z" /><path d="M12 8v4m0 4h.01" /></>,
    report: <><path d="M5 3h10l4 4v14H5z" /><path d="M15 3v5h5M8 12h8m-8 4h8" /></>,
    users: <><path d="M16 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" /><circle cx="10" cy="7" r="4" /><path d="M20 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75" /></>,
    search: <><circle cx="10.8" cy="10.8" r="6.8" /><path d="m16 16 5 5" /></>,
    bell: <><path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9m-8 12h4" /></>,
    help: <><circle cx="12" cy="12" r="9" /><path d="M9.6 9a2.5 2.5 0 1 1 4.5 1.5c-1.2 1.2-2.1 1.5-2.1 3m0 3h.01" /></>,
    chevron: <><path d="m8 10 4 4 4-4" /></>,
    sun: <><circle cx="12" cy="12" r="4" /><path d="M12 2v2m0 16v2M4.93 4.93l1.42 1.42m11.3 11.3 1.42 1.42M2 12h2m16 0h2M4.93 19.07l1.42-1.42m11.3-11.3 1.42-1.42" /></>,
  };

  return (
    <svg aria-hidden="true" className="icon" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
      {paths[name]}
    </svg>
  );
}

async function request(path, options = {}) {
  const { headers: requestHeaders, ...fetchOptions } = options;
  const response = await fetch(`${REQUEST_BASE_URL}${path}`, {
    ...fetchOptions,
    headers: { "Content-Type": "application/json", ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}), ...(requestHeaders || {}) },
  });

  if (!response.ok) {
    let message = `Request failed with status ${response.status}.`;
    try {
      const payload = await response.json();
      message = payload.detail || message;
    } catch {
      // Keep the useful HTTP error when the API did not return JSON.
    }
    if (response.status === 401 && accessToken) {
      accessToken = "";
      window.dispatchEvent(new Event("securcode-session-expired"));
    }
    const error = new Error(message);
    error.status = response.status;
    throw error;
  }

  return response.json();
}

async function downloadReport(path, filename) {
  const response = await fetch(`${REQUEST_BASE_URL}${path}`, { headers: accessToken ? { Authorization: `Bearer ${accessToken}` } : {} });
  if (!response.ok) throw new Error(`Report download failed with status ${response.status}.`);
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
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

function SeverityDonut({ counts = {} }) {
  const total = severities.reduce((sum, level) => sum + Number(counts[level] || 0), 0);
  const palette = { CRITICAL: "#b42318", HIGH: "#d95040", MEDIUM: "#d68a13", LOW: "#16865b" };
  let offset = 0;
  const segments = severities.map((level) => {
    const value = Number(counts[level] || 0);
    const length = total ? (value / total) * 100 : 0;
    const segment = { level, value, length, offset, color: palette[level] };
    offset += length;
    return segment;
  });
  return <div className="donut-layout"><div className="donut-chart" role="img" aria-label={`Severity distribution: ${segments.map((item) => `${item.level} ${item.value}`).join(", ")}`}><svg viewBox="0 0 120 120"><circle className="donut-track" cx="60" cy="60" r="44" />{segments.map((item) => <circle key={item.level} cx="60" cy="60" r="44" fill="none" stroke={item.color} strokeWidth="12" pathLength="100" strokeDasharray={`${item.length} ${100 - item.length}`} strokeDashoffset={-item.offset} transform="rotate(-90 60 60)"><title>{item.level}: {item.value}</title></circle>)}</svg><div className="donut-center"><strong>{formatNumber(total)}</strong><span>findings</span></div></div><div className="donut-legend">{segments.map((item) => <div key={item.level}><i style={{ backgroundColor: item.color }} /><span>{item.level}</span><strong>{formatNumber(item.value)}</strong></div>)}</div></div>;
}

function FindingsTrend({ trends = [] }) {
  const points = trends.slice(-14);
  if (!points.length) return <div className="chart-empty">No scan history yet. Run a scan to build a trend.</div>;
  const width = 560; const height = 190; const left = 36; const right = 12; const top = 12; const bottom = 34;
  const max = Math.max(1, ...points.map((point) => Number(point.findings || 0)));
  const coords = points.map((point, index) => ({ x: left + (points.length === 1 ? (width - left - right) / 2 : index * (width - left - right) / (points.length - 1)), y: top + (height - top - bottom) * (1 - Number(point.findings || 0) / max), ...point }));
  return <div className="trend-chart-wrap"><svg className="trend-chart" viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Daily findings trend from recorded scans"><line x1={left} y1={top} x2={left} y2={height - bottom} /><line x1={left} y1={height - bottom} x2={width - right} y2={height - bottom} /><line x1={left} y1={top + (height - top - bottom) / 2} x2={width - right} y2={top + (height - top - bottom) / 2} /><text x="2" y={top + 4}>{max}</text><text x="12" y={height - bottom + 4}>0</text><polyline points={coords.map((point) => `${point.x},${point.y}`).join(" ")} />{coords.map((point) => <g key={point.date}><circle cx={point.x} cy={point.y} r="3.5"><title>{point.date}: {point.findings} findings across {point.scans} scans</title></circle></g>)}{coords.filter((_, index) => index === 0 || index === coords.length - 1 || index === Math.floor(coords.length / 2)).map((point) => <text className="axis-date" key={`label-${point.date}`} x={point.x} y={height - 8} textAnchor="middle">{point.date.slice(5)}</text>)}</svg><div className="chart-caption"><span><i className="legend-line" />Findings per day</span><span>Daily total from persisted scan results</span></div></div>;
}

function EmptyTable({ children, colSpan }) {
  return <tr><td className="empty-cell" colSpan={colSpan}>{children}</td></tr>;
}

function App() {
  const [authReady, setAuthReady] = useState(false);
  const [authUser, setAuthUser] = useState(null);
  const [authForm, setAuthForm] = useState({ username: "", password: "" });
  const [authError, setAuthError] = useState("");
  const [authBusy, setAuthBusy] = useState(false);
  const [activeNav, setActiveNav] = useState("Overview");
  const [theme, setTheme] = useState(() => window.localStorage.getItem("securcode-theme") || "light");
  const [globalSearch, setGlobalSearch] = useState("");
  const [collapsedGroups, setCollapsedGroups] = useState({});
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [data, setData] = useState({ status: null, stats: null, history: null });
  const [watcherData, setWatcherData] = useState({ status: null, findings: null, error: "" });
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [connectionError, setConnectionError] = useState("");
  const [scanPath, setScanPath] = useState("");
  const [scanState, setScanState] = useState("idle");
  const [scanMessage, setScanMessage] = useState("");
  const [historyRefreshState, setHistoryRefreshState] = useState("idle");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [languageFilter, setLanguageFilter] = useState("ALL");
  const [selectedScanId, setSelectedScanId] = useState("ALL");
  const inputRef = useRef(null);
  const globalSearchRef = useRef(null);
  const findingsSectionRef = useRef(null);
  const canRunScan = Boolean(data.status?.demo_mode) || ["administrator", "security_analyst", "developer"].includes(authUser?.role);

  async function loadDashboard(isRefresh = false) {
    if (isRefresh) setRefreshing(true);
    else setLoading(true);

    const results = await Promise.allSettled([
      request("/status"),
      request("/dashboard"),
      request("/history?limit=20"),
      Promise.all(["Open", "Investigating", "Contained"].map((incidentStatus) => request(`/incidents?status=${encodeURIComponent(incidentStatus)}&limit=1`))),
      request("/notifications?limit=1"),
    ]);
    const [status, stats, history, incidents, notifications] = results;
    const nextData = {
      status: status.status === "fulfilled" ? status.value : null,
      stats: stats.status === "fulfilled" ? stats.value : null,
      history: history.status === "fulfilled" ? history.value : null,
      activeIncidents: incidents.status === "fulfilled" ? incidents.value.reduce((total, result) => total + Number(result.total || 0), 0) : null,
      unreadNotifications: notifications.status === "fulfilled" ? Number(notifications.value.unread_count || 0) : 0,
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
    request("/status").then((status) => {
      if (status.demo_mode) setAuthUser({ username: "Public demo", role: "read_only", demo: true });
    }).catch((error) => setAuthError(error.message)).finally(() => setAuthReady(true));
  }, []);

  useEffect(() => {
    const expireSession = () => setAuthUser(null);
    window.addEventListener("securcode-session-expired", expireSession);
    return () => window.removeEventListener("securcode-session-expired", expireSession);
  }, []);

  useEffect(() => {
    if (authUser) loadDashboard();
  }, [authUser]);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    window.localStorage.setItem("securcode-theme", theme);
  }, [theme]);

  useEffect(() => {
    function handleSearchShortcut(event) {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        globalSearchRef.current?.focus();
      }
    }
    window.addEventListener("keydown", handleSearchShortcut);
    return () => window.removeEventListener("keydown", handleSearchShortcut);
  }, []);

  async function handleLogin(event) {
    event.preventDefault();
    setAuthBusy(true);
    setAuthError("");
    try {
      const result = await request("/auth/login", { method: "POST", body: JSON.stringify(authForm) });
      accessToken = result.access_token;
      setAuthUser(result.user);
      setAuthForm({ username: "", password: "" });
    } catch (error) {
      setAuthError(error.message);
    } finally {
      setAuthBusy(false);
    }
  }

  async function handleLogout() {
    try { if (accessToken) await request("/auth/logout", { method: "POST" }); } catch { /* session may already have expired */ }
    accessToken = "";
    setAuthUser(null);
  }

  useEffect(() => {
    if (!authUser) return undefined;
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
  }, [authUser]);

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
    setHistoryRefreshState("idle");
    try {
      const result = await request("/scan", {
        method: "POST",
        body: JSON.stringify({ project_path: projectPath }),
      });
      setSeverityFilter("ALL");
      setLanguageFilter("ALL");
      const status = result.status || "failed";
      if (status === "completed") {
        const refreshedData = await loadDashboard(true);
        const latestScan = refreshedData.history?.scans?.[0];
        if (latestScan) {
          setSelectedScanId(String(latestScan.id));
        }
        setScanState("success");
        setScanMessage(`Scan completed with ${formatNumber(result.total_findings)} finding${result.total_findings === 1 ? "" : "s"}.`);
      } else {
        await refreshHistoryAfterFailedScan({
          loadHistory: () => request("/history?limit=20"),
          onHistory: (history) => {
            setData((current) => ({ ...current, history }));
            const latestScan = history.scans?.[0];
            if (latestScan) setSelectedScanId(String(latestScan.id));
          },
          onState: setHistoryRefreshState,
        });
        setScanState(status === "partial" ? "partial" : "error");
        const errors = (result.errors || []).map((error) => error.message).filter(Boolean);
        setScanMessage(
          `${status === "partial" ? "Scan partially completed" : "Scan failed"}; ${formatNumber(result.total_findings)} finding${result.total_findings === 1 ? "" : "s"} collected.${errors.length ? ` ${errors.join(" ")}` : ""}`,
        );
      }
    } catch (error) {
      setScanState("error");
      setScanMessage(error.message);
      await refreshHistoryAfterFailedScan({
        loadHistory: () => request("/history?limit=20"),
        onHistory: (history) => {
          setData((current) => ({ ...current, history }));
          const latestScan = history.scans?.[0];
          if (latestScan) setSelectedScanId(String(latestScan.id));
        },
        onState: setHistoryRefreshState,
      });
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
    if (label === "Overview") {
      loadDashboard(true);
    }
    if (label === "Scans") {
      inputRef.current?.focus();
    }
  }

  function selectScan(scanId) {
    setSelectedScanId(scanId);
    setSeverityFilter("ALL");
    setLanguageFilter("ALL");
    findingsSectionRef.current?.scrollIntoView({ block: "start" });
  }

  if (!authReady) return <div className="auth-shell"><section className="auth-card"><span className="brand-mark"><Icon name="shield" size={20} /></span><h1>Connecting to SecurCode</h1><p>Checking instance access policy…</p></section></div>;
  if (!authUser) return <div className="auth-shell"><form className="auth-card" onSubmit={handleLogin}><span className="brand-mark"><Icon name="shield" size={20} /></span><span className="section-label">SECURE WORKSPACE</span><h1>Sign in to SecurCode</h1><p>Use your administrator-provisioned account.</p>{authError && <div className="api-alert" role="alert">{authError}</div>}<label>Username<input required minLength="3" autoComplete="username" value={authForm.username} onChange={(event) => setAuthForm({ ...authForm, username: event.target.value })} /></label><label>Password<input required minLength="12" type="password" autoComplete="current-password" value={authForm.password} onChange={(event) => setAuthForm({ ...authForm, password: event.target.value })} /></label><button className="button button-primary" disabled={authBusy}>{authBusy ? "Signing in…" : "Sign in"}</button><small>First administrator accounts must be initialized by the operator with the configured bootstrap token.</small></form></div>;

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="topbar-brand"><span className="brand-mark"><Icon name="shield" size={20} /></span><span>SecurCode<small>APPLICATION SECURITY</small></span></div>
        <div className="workspace-selector"><span className="workspace-avatar">S</span><span><small>WORKSPACE</small><strong>Default workspace</strong></span><Icon name="chevron" size={14} /></div>
        <div className="breadcrumb" aria-label="Breadcrumb"><span>Security</span><span className="breadcrumb-separator">/</span><strong>{activeNav}</strong></div>
        <label className="global-search"><Icon name="search" size={16} /><input ref={globalSearchRef} aria-label="Search findings" value={globalSearch} placeholder="Search findings, rules, files…" onFocus={() => chooseNav("Vulnerabilities")} onChange={(event) => { setGlobalSearch(event.target.value); chooseNav("Vulnerabilities"); }} /><kbd>Ctrl K</kbd></label>
        <div className="topbar-actions">
          <div className={`connection-state ${connectionHealthy ? "is-healthy" : "is-offline"}`} title={connectionError || (connectionHealthy ? "API connection healthy" : "Checking API connection")}><span className="connection-dot" /> <span>{connectionHealthy ? "API connected" : loading ? "Connecting" : "API unavailable"}</span></div>
          <button className="icon-button notification-button" aria-label={`View notifications${data.unreadNotifications ? `, ${data.unreadNotifications} unread` : ""}`} title="Notifications" onClick={() => chooseNav("Notifications")}><Icon name="bell" size={17} />{data.unreadNotifications > 0 && <i />}</button>
          <a className="icon-button topbar-link" href={`${import.meta.env.DEV && !CONFIGURED_API_BASE_URL ? "/api" : API_BASE_URL}/docs`} target="_blank" rel="noreferrer" aria-label="Help and API documentation"><Icon name="help" size={17} /></a>
          <button className="icon-button theme-toggle" aria-label="Toggle color theme" title="Toggle color theme" onClick={() => setTheme((current) => current === "light" ? "dark" : "light")}><Icon name="sun" size={17} /></button>
          <button className="profile-chip" onClick={authUser.demo ? () => chooseNav("Settings") : handleLogout} aria-label={authUser.demo ? "Read only public demo profile" : "Sign out"}><span>{authUser.username.slice(0, 2).toUpperCase()}</span><b>{authUser.username} · {authUser.role.replaceAll("_", " ")}</b><Icon name="chevron" size={13} /></button>
          <button className="icon-button mobile-menu-button" onClick={() => setMobileNavOpen((open) => !open)} aria-label={mobileNavOpen ? "Close navigation" : "Open navigation"}><Icon name={mobileNavOpen ? "close" : "menu"} /></button>
        </div>
      </header>

      <div className="workspace">
        <aside className={`sidebar ${mobileNavOpen ? "sidebar-open" : ""}`}>
          <nav aria-label="Primary navigation">
            {[...new Set(navigation.map((item) => item.group))].map((group) => <div className="nav-group" key={group}><button className="sidebar-heading nav-group-toggle" aria-expanded={!collapsedGroups[group]} onClick={() => setCollapsedGroups((current) => ({ ...current, [group]: !current[group] }))}>{group}<Icon name="chevron" size={13} /></button>{!collapsedGroups[group] && navigation.filter((item) => item.group === group).map((item) => <button key={item.label} className={`nav-item ${activeNav === item.label ? "nav-item-active" : ""}`} onClick={() => chooseNav(item.label)}><Icon name={item.icon} size={17} /><span>{item.label}</span></button>)}</div>)}
          </nav>
          <div className="sidebar-footer"><span className="sidebar-footer-label">API endpoint</span><code>{API_BASE_URL.replace(/^https?:\/\//, "")}</code></div>
        </aside>

        <main className="main-content">
          {activeNav === "Overview" ? <>
          <div className="page-header">
            <div><h1>Security Overview</h1><p>Review current scan coverage and resolve findings across your workspace.</p></div>
            {canRunScan && <button className="button button-primary" onClick={() => inputRef.current?.focus()}><Icon name="scan" size={16} />Run new scan</button>}
          </div>

          {canRunScan && <section className="scan-action" aria-labelledby="scan-action-title">
            <div className="scan-action-copy"><span className="section-label">Scan workspace</span><h2 id="scan-action-title">Start a security scan</h2><p>Use a relative directory path inside the backend workspace.</p></div>
            <form className="scan-form" onSubmit={handleScan}>
              <label className="sr-only" htmlFor="project-path">Project path</label>
              <input ref={inputRef} id="project-path" value={scanPath} onChange={(event) => { setScanPath(event.target.value); if (scanState !== "idle") setScanState("idle"); }} placeholder="Bundled sample: backend/app/api/docs/security-demo" disabled={scanState === "loading"} />
              <button className="button button-primary" type="submit" disabled={scanState === "loading"}>{scanState === "loading" ? <><span className="button-spinner" />Scanning</> : <>Scan project <Icon name="arrow" size={15} /></>}</button>
            </form>
            {scanState !== "idle" && <div className={`scan-feedback feedback-${scanState}`} role={scanState === "error" ? "alert" : "status"}><span className="feedback-icon">{scanState === "success" ? "✓" : scanState === "error" ? "!" : "·"}</span>{scanMessage}</div>}
            {historyRefreshState !== "idle" && <div className={`history-refresh-status history-${historyRefreshState}`} role={historyRefreshState === "stale" ? "alert" : "status"}>{historyRefreshState === "refreshing" ? "Refreshing scan history…" : historyRefreshState === "refreshed" ? "Scan history refreshed." : "Scan history could not be refreshed; displayed history may be stale. Use Refresh data to retry."}</div>}
          </section>}

          <section className="table-section" aria-labelledby="watcher-title">
            <div className="section-heading">
              <div><h2 id="watcher-title">Live file watcher</h2><p>Latest findings from a changed source file in the watched demo directory.</p></div>
              <StatusBadge status={watcherData.status ? (watcherData.status.running ? "running" : "stopped") : watcherData.error ? "unavailable" : "connecting"} />
            </div>
            {watcherData.error ? <div className="api-alert" role="alert"><div><strong>Watcher data is unavailable</strong><span>{watcherData.error}</span></div></div> : watcherData.findings?.error ? <div className="api-alert" role="alert"><div><strong>Latest file scan failed</strong><span>{watcherData.findings.error}</span></div></div> : <>
              <div className="findings-context"><span>Last file</span><strong title={watcherData.findings?.last_file || ""}>{watcherData.findings?.last_file ? shortPath(watcherData.findings.last_file) : "No file changes detected yet"}</strong><span>{formatNumber(watcherData.findings?.total_findings)} findings</span></div>
              <div className="table-wrap"><table><thead><tr><th>Severity</th><th>Rule ID</th><th>Line</th><th>Description</th></tr></thead><tbody>{!watcherData.findings ? <EmptyTable colSpan="4">Waiting for watcher results.</EmptyTable> : watcherData.findings.findings.length === 0 ? <EmptyTable colSpan="4">The latest changed file has no findings.</EmptyTable> : watcherData.findings.findings.map((finding, index) => <tr key={`${finding.test_id}-${finding.line_number}-${index}`}><td><span className={severityClass(finding.severity)}>{finding.severity || "Unknown"}</span></td><td><code className="rule-id">{finding.test_id || "-"}</code></td><td className="numeric-value">{finding.line_number ?? "-"}</td><td><span className="description-value">{finding.description || "No description provided."}</span></td></tr>)}</tbody></table></div>
            </>}
          </section>

          {connectionError && <div className="api-alert" role="alert"><div><strong>{data.status ? "Some dashboard data is unavailable" : "Unable to reach the SecurCode API"}</strong><span>{connectionError} Check that the backend is running at {API_BASE_URL}.</span></div><button className="button button-secondary" onClick={() => loadDashboard(true)} disabled={refreshing}><Icon name="refresh" size={15} />Retry</button></div>}
          {!loading && Number(data.stats?.open_finding_severity_counts?.CRITICAL || 0) > 0 && <div className="api-alert critical-notice" role="status"><div><strong>{formatNumber(data.stats.open_finding_severity_counts.CRITICAL)} open critical finding{data.stats.open_finding_severity_counts.CRITICAL === 1 ? "" : "s"}</strong><span>Review the stored evidence and choose a lifecycle status.</span></div><button className="button button-secondary" onClick={() => chooseNav("Vulnerabilities")}>Review findings</button></div>}

          <section className="metrics-section" aria-labelledby="metrics-title">
            <div className="section-heading"><div><h2 id="metrics-title">Security posture</h2><p>Current stored findings and workflow state across recorded scans.</p></div><button className="text-button" onClick={() => loadDashboard(true)} disabled={refreshing}><Icon name="refresh" size={14} />{refreshing ? "Refreshing" : "Refresh data"}</button></div>
            <div className="metric-grid"><Metric label="Total scans" value={data.stats?.total_scans} icon="scan" loading={loading} /><Metric label="Open vulnerabilities" value={Number(data.stats?.finding_status_counts?.Open || 0) + Number(data.stats?.finding_status_counts?.["In Progress"] || 0)} icon="finding" loading={loading} tone="amber" /><Metric label="Critical findings" value={data.stats?.severity_counts?.CRITICAL} icon="finding" loading={loading} tone="red" /><Metric label="High findings" value={data.stats?.severity_counts?.HIGH} icon="finding" loading={loading} tone="red" /><Metric label="Active incidents" value={data.activeIncidents} icon="incident" loading={loading} tone="amber" /><Metric label="Risk posture index" value={data.stats?.risk_score} icon="shield" loading={loading} /></div>
            {!loading && data.stats && <p className="risk-score">Risk posture index <strong>{data.stats.risk_score}/100</strong><span>{data.stats.risk_score_method}</span></p>}
          </section>

          <section className="dashboard-grid" aria-label="Security posture breakdown">
            <div className="dashboard-panel"><div className="section-heading"><div><h2>Severity distribution</h2><p>Latest stored finding state by severity.</p></div></div><SeverityDonut counts={data.stats?.severity_counts} /></div>
            <div className="dashboard-panel"><div className="section-heading"><div><h2>Remediation state</h2><p>Lifecycle state for tracked findings.</p></div></div>{["Open", "In Progress", "Resolved", "Accepted Risk", "False Positive"].map((state) => <div className="chart-row" key={state}><span>{state}</span><div className="chart-track"><span className="chart-bar chart-bar-neutral" style={{ width: `${Math.min(100, (data.stats?.finding_status_counts?.[state] || 0) / Math.max(1, data.stats?.total_findings || 0) * 100)}%` }} /></div><strong>{formatNumber(data.stats?.finding_status_counts?.[state] || 0)}</strong></div>)}</div>
            <div className="dashboard-panel trend-panel"><div className="section-heading"><div><h2>Daily scan findings</h2><p>Finding totals reported by scans each day; repeat detections may appear again.</p></div></div><FindingsTrend trends={data.stats?.trends || []} /></div>
            <div className="dashboard-panel"><div className="section-heading"><div><h2>Most affected projects</h2><p>Recorded findings by project.</p></div></div>{!data.stats?.most_affected_projects?.length ? <p className="chart-empty">Projects appear after a scan is recorded.</p> : data.stats.most_affected_projects.map((project) => { const max = Math.max(1, ...data.stats.most_affected_projects.map((item) => Number(item.findings || 0))); return <div className="project-risk-row" key={project.id}><div><span title={project.project_path}>{project.name || shortPath(project.project_path)}</span><strong>{formatNumber(project.findings)}</strong></div><div className="chart-track"><span className="chart-bar severity-bar-high" style={{ width: `${Number(project.findings || 0) / max * 100}%` }} /></div></div>; })}</div>
            <div className="dashboard-panel"><div className="section-heading"><div><h2>Recent scans</h2><p>Latest project analysis results.</p></div><button className="text-button" onClick={() => chooseNav("Scans")}>View all</button></div>{!data.history?.scans?.length ? <p className="chart-empty">No scans recorded.</p> : data.history.scans.slice(0, 4).map((scan) => <div className="trend-row" key={scan.id}><span title={scan.project_path}>{shortPath(scan.project_path)}</span><strong>{formatNumber(scan.total_findings)} findings</strong></div>)}</div>
            <div className="dashboard-panel"><div className="section-heading"><div><h2>Recent incidents</h2><p>Current response activity.</p></div><button className="text-button" onClick={() => chooseNav("Incidents")}>View all</button></div>{!data.stats?.recent_incidents?.length ? <p className="chart-empty">No incidents recorded.</p> : data.stats.recent_incidents.map((incident) => <div className="trend-row" key={incident.id}><span>{incident.title}</span><strong>{incident.priority} · {incident.status}</strong></div>)}</div>
            <div className="dashboard-panel"><div className="section-heading"><div><h2>Service health</h2><p>API, database, scanner, and live watcher state.</p></div></div>{[["API", data.status?.status], ["Database", data.status?.database], ["Scanner", data.status?.scanner], ["File watcher", watcherData.status?.running ? "running" : watcherData.error ? "unavailable" : "connecting"]].map(([label, value]) => <div className="trend-row" key={label}><span>{label}</span><strong className={value === "healthy" || value === "available" || value === "running" ? "health-good" : "health-muted"}>{value || "unknown"}</strong></div>)}</div>
          </section>

          <section className="table-section" aria-labelledby="recent-scans-title">
            <div className="section-heading"><div><h2 id="recent-scans-title">Recent scans</h2><p>Most recent project activity from the scan history.</p></div><span className="table-count">{data.history ? `${formatNumber(data.history.total)} total` : "--"}</span></div>
            <div className="table-wrap"><table><thead><tr><th>Status</th><th>Project path</th><th>Findings</th><th>Scanned</th><th>Inspect</th></tr></thead><tbody>{loading ? <><tr><td colSpan="5"><div className="table-skeleton" /></td></tr><tr><td colSpan="5"><div className="table-skeleton short" /></td></tr></> : !data.history ? <EmptyTable colSpan="5">Scan history could not be loaded. Retry the API request to view recorded activity.</EmptyTable> : scans.length === 0 ? <EmptyTable colSpan="5">No scans have been recorded yet. Start a scan above to populate this history.</EmptyTable> : scans.map((scan) => <tr key={scan.id}><td><StatusBadge status={scan.status} /></td><td><span className="path-value" title={scan.project_path}>{shortPath(scan.project_path)}</span></td><td className="numeric-value">{formatNumber(scan.total_findings)}</td><td className="muted-value">{formatTimestamp(scan.created_at)}</td><td><button className="table-action" type="button" onClick={() => selectScan(String(scan.id))}>View findings <Icon name="arrow" size={13} /></button></td></tr>)}</tbody></table></div>
           </section>

          <section ref={findingsSectionRef} className="table-section findings-section" aria-labelledby="findings-title">
            <div className="section-heading"><div><h2 id="findings-title">Findings Explorer</h2><p>Inspect stored findings from the loaded scan history.</p></div><div className="section-tools"><label className="filter-label" htmlFor="scan-filter">Scan</label><select id="scan-filter" value={selectedScanValue} onChange={(event) => selectScan(event.target.value)} disabled={!data.history || loading}><option value="ALL">All loaded scans</option>{scans.map((scan) => <option key={scan.id} value={scan.id}>{shortPath(scan.project_path)} · {formatTimestamp(scan.created_at)}</option>)}</select><label className="filter-label" htmlFor="severity-filter">Severity</label><select id="severity-filter" value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)} disabled={!data.history || loading}><option value="ALL">All severities</option><option value="HIGH">High</option><option value="CRITICAL">Critical</option><option value="MEDIUM">Medium</option><option value="LOW">Low</option></select>{languageFilterSupported && <><label className="filter-label" htmlFor="language-filter">Language</label><select id="language-filter" value={languageFilter} onChange={(event) => setLanguageFilter(event.target.value)} disabled={!data.history || loading}><option value="ALL">All languages</option>{languages.map((language) => <option key={language} value={language}>{language}</option>)}</select></>}<span className="table-count">{data.history ? `${formatNumber(findings.length)} of ${formatNumber(scopedFindings.length)}` : "--"}</span></div></div>
            {selectedScan && <><div className="findings-context"><span>Selected historical scan</span><strong title={selectedScan.project_path}>{shortPath(selectedScan.project_path)}</strong><span>{formatTimestamp(selectedScan.created_at)} · {formatNumber(selectedScan.total_findings)} stored findings</span></div>{selectedScan.errors?.length > 0 && <div className="api-alert" role="alert"><div><strong>Scan was {selectedScan.status}</strong>{selectedScan.errors.map((error, index) => <span key={`${error.path}-${index}`}>{error.message}</span>)}</div></div>}</>}
            <div className="table-wrap"><table className="findings-table"><thead><tr><th>Severity</th><th>Language</th><th>Rule ID</th><th>File</th><th>Line</th><th>Confidence</th><th>Description</th></tr></thead><tbody>{loading ? <><tr><td colSpan="7"><div className="table-skeleton" /></td></tr><tr><td colSpan="7"><div className="table-skeleton short" /></td></tr></> : !data.history ? <EmptyTable colSpan="7">Finding data could not be loaded because scan history is unavailable.</EmptyTable> : findings.length === 0 ? <EmptyTable colSpan="7">{selectedScan ? "No findings are stored for this scan or the filters match no findings." : "No findings match the selected filters."}</EmptyTable> : findings.map((finding, index) => <tr key={`${finding.test_id}-${finding.filename}-${finding.line_number}-${index}`}><td><span className={severityClass(finding.severity)}>{finding.severity || "Unknown"}</span></td><td><span className="language-value">{finding.language || "Unknown"}</span></td><td><code className="rule-id">{finding.test_id || "-"}</code></td><td><span className="file-value" title={finding.filename}>{shortPath(finding.filename)}</span></td><td className="numeric-value">{finding.line_number ?? "-"}</td><td><span className="confidence-value">{finding.confidence || "Unknown"}</span></td><td><span className="description-value">{finding.description || "No description provided."}</span></td></tr>)}</tbody></table></div>
          </section>

          <footer className="content-footer"><span>SecurCode Security Scanner</span><span>API: {API_BASE_URL}</span></footer>
          </> : <PlatformPage section={activeNav} request={request} readOnly={data.status?.read_only} role={authUser.role} userId={authUser.id} downloadReport={downloadReport} onNavigate={chooseNav} onNotificationsChange={() => loadDashboard(true)} globalSearch={globalSearch} />}
        </main>
      </div>
    </div>
  );
}

createRoot(document.getElementById("root")).render(<App />);
