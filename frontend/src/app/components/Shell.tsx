import { useEffect, useState, type ReactNode } from "react";
import { NavLink, Outlet, useLocation, useNavigate, useParams } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";
import { ROLE_LABELS } from "../lib/format";
import type { Notification } from "../lib/types";
import { Button, cx } from "./ui";

export function Logo({ className }: { className?: string }) {
  return (
    <span className={cx("inline-flex items-center gap-2 font-semibold tracking-tight text-fg", className)}>
      <span className="grid h-7 w-7 place-items-center rounded-[2px] border border-accent/50 text-accent-strong" aria-hidden>
        <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M12 3 20 6v5.3c0 4.6-3.1 8-8 9.7-4.9-1.7-8-5.1-8-9.7V6l8-3Z" /><path d="m8.5 12 2.2 2.2 4.8-4.8" /></svg>
      </span>
      SecurCode
    </span>
  );
}

export function ThemeToggle() {
  const [theme, setTheme] = useState(() => document.documentElement.dataset.theme ?? "dark");
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try { localStorage.setItem("securcode-theme", theme); } catch { /* storage unavailable */ }
  }, [theme]);
  return (
    <Button variant="ghost" aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`} onClick={() => setTheme(theme === "dark" ? "light" : "dark")}>
      {theme === "dark" ? "Light" : "Dark"}
    </Button>
  );
}

function OrgSwitcher() {
  const { session, setSession } = useAuth();
  const { orgId } = useParams();
  const navigate = useNavigate();
  if (!session || session.organizations.length === 0) return null;
  return (
    <label className="flex items-center gap-2 text-xs text-muted">
      <span className="sr-only sm:not-sr-only">Organization</span>
      <select
        aria-label="Switch organization"
        className="max-w-[220px] rounded-[3px] border border-line bg-inset px-2 py-1 text-[13px] text-fg"
        value={orgId ?? session.active_org_id ?? ""}
        onChange={async (event) => {
          const next = event.target.value;
          if (next === "__new") { navigate("/onboarding"); return; }
          const payload = await api.post<typeof session>("/auth/me/active-organization", { org_id: next });
          setSession(payload);
          navigate(`/orgs/${next}/dashboard`);
        }}
      >
        {session.organizations.map((org) => <option key={org.id} value={org.id}>{org.name}{org.is_demo ? " (demo)" : ""}</option>)}
        <option value="__new">+ New organization…</option>
      </select>
    </label>
  );
}

function NotificationBell() {
  const { data } = useQuery({
    queryKey: ["notifications", "count"],
    queryFn: () => api.get<{ unread: number; items: Notification[] }>("/notifications", { limit: 1 }),
    refetchInterval: 30_000,
  });
  const unread = data?.unread ?? 0;
  return (
    <NavLink to="/notifications" className="relative rounded-[3px] px-2 py-1.5 text-[13px] text-muted hover:bg-raised hover:text-fg" aria-label={`Notifications, ${unread} unread`}>
      Notifications
      {unread > 0 && <span className="tabular ml-1.5 rounded-full bg-accent px-1.5 text-[11px] font-semibold text-accent-ink">{unread > 99 ? "99+" : unread}</span>}
    </NavLink>
  );
}

function UserMenu() {
  const { session, logout } = useAuth();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  if (!session) return null;
  return (
    <div className="relative">
      <Button variant="ghost" aria-haspopup="menu" aria-expanded={open} onClick={() => setOpen(!open)}>
        <span className="max-w-[160px] truncate">{session.user.display_name || session.user.email}</span>
      </Button>
      {open && (
        <div role="menu" className="absolute right-0 z-20 mt-1 w-56 border border-line bg-surface py-1 shadow-lg" onMouseLeave={() => setOpen(false)}>
          <div className="border-b border-line px-3 py-2 text-xs text-muted">{session.user.email}</div>
          {[["/account", "Profile"], ["/account/security", "Account security"], ["/notifications", "Notifications"],
            ...(session.user.is_platform_admin ? [["/admin", "Platform administration"]] : [])].map(([to, label]) => (
            <button key={to} role="menuitem" type="button" className="block w-full px-3 py-1.5 text-left text-[13px] text-fg hover:bg-raised" onClick={() => { setOpen(false); navigate(to); }}>{label}</button>
          ))}
          <button role="menuitem" type="button" className="block w-full border-t border-line px-3 py-1.5 text-left text-[13px] text-critical hover:bg-raised"
            onClick={async () => { await logout(); navigate("/login"); }}>Sign out</button>
        </div>
      )}
    </div>
  );
}

const NAV: { group: string; items: { to: string; label: string; permission?: string }[] }[] = [
  { group: "Security", items: [
    { to: "dashboard", label: "Dashboard" }, { to: "projects", label: "Projects" }, { to: "scans", label: "Scans" },
    { to: "findings", label: "Vulnerabilities" }, { to: "remediation", label: "My remediation" },
    { to: "reviews", label: "Reviews" }, { to: "analytics", label: "Analytics" },
  ] },
  { group: "Governance", items: [
    { to: "reports", label: "Reports" }, { to: "audit", label: "Audit log", permission: "audit.view" },
    { to: "policy", label: "Security policy" }, { to: "schedules", label: "Scheduled scans" },
  ] },
  { group: "Organization", items: [
    { to: "integrations", label: "GitHub integration", permission: "integrations.view" },
    { to: "team", label: "Team & invitations" }, { to: "settings", label: "Settings" },
  ] },
];

function Sidebar({ onNavigate }: { onNavigate?: () => void }) {
  const { orgId } = useParams();
  const { session } = useAuth();
  const org = session?.organizations.find((item) => item.id === orgId);
  if (!org) return null;
  return (
    <nav aria-label="Organization navigation" className="space-y-5 px-3 py-4">
      <div className="px-2">
        <div className="truncate text-[13px] font-semibold text-fg">{org.name}</div>
        <div className="text-xs text-faint">{ROLE_LABELS[org.role]}</div>
      </div>
      {NAV.map((group) => (
        <div key={group.group}>
          <div className="mb-1 px-2 text-[11px] font-medium uppercase tracking-wider text-faint">{group.group}</div>
          <ul className="space-y-px">
            {group.items.filter((item) => !item.permission || org.permissions.includes(item.permission)).map((item) => (
              <li key={item.to}>
                <NavLink to={`/orgs/${org.id}/${item.to}`} onClick={onNavigate}
                  className={({ isActive }) => cx("block rounded-[3px] px-2 py-1.5 text-[13px]", isActive ? "bg-accent-soft/60 text-fg" : "text-muted hover:bg-raised hover:text-fg")}>
                  {item.label}
                </NavLink>
              </li>
            ))}
          </ul>
        </div>
      ))}
    </nav>
  );
}

export function TopBar({ menuButton }: { menuButton?: ReactNode }) {
  return (
    <header className="sticky top-0 z-10 flex h-14 items-center gap-3 border-b border-line bg-topbar px-4">
      {menuButton}
      <NavLink to="/" aria-label="SecurCode home"><Logo /></NavLink>
      <div className="ml-auto flex items-center gap-1 sm:gap-3">
        <OrgSwitcher />
        <NotificationBell />
        <ThemeToggle />
        <UserMenu />
      </div>
    </header>
  );
}

export function AppShell() {
  const [menu, setMenu] = useState(false);
  const location = useLocation();
  const { orgId } = useParams();
  useEffect(() => setMenu(false), [location.pathname]);
  return (
    <div className="min-h-screen bg-bg">
      <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:left-2 focus:top-2 focus:z-50 focus:bg-surface focus:p-2">Skip to content</a>
      <TopBar menuButton={orgId ? <Button variant="ghost" className="lg:hidden" aria-label="Open navigation" aria-expanded={menu} onClick={() => setMenu(!menu)}>Menu</Button> : undefined} />
      <div className="flex">
        {orgId && (
          <aside className={cx("w-60 shrink-0 border-r border-line bg-sidebar", "fixed inset-y-14 left-0 z-10 overflow-y-auto lg:static lg:block", menu ? "block" : "hidden")}>
            <Sidebar onNavigate={() => setMenu(false)} />
          </aside>
        )}
        <main id="main" className="min-w-0 flex-1 px-4 py-6 sm:px-8">
          <div className="mx-auto max-w-7xl"><Outlet /></div>
        </main>
      </div>
    </div>
  );
}
