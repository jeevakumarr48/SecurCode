import { Component, Suspense, lazy, type ReactNode } from "react";
import { Navigate, Outlet, Route, Routes, useLocation, useParams } from "react-router";
import { useAuth } from "./lib/auth";
import { AppShell } from "./components/Shell";
import { ButtonLink, ErrorState, Skeleton } from "./components/ui";
import { AcceptInvitationPage, ForgotPasswordPage, LandingPage, LoginPage, RegisterPage, ResetPasswordPage, VerifyEmailPage } from "./pages/public";

// Authenticated areas are code-split so the public pages stay small; charts load only with the dashboard.
const dashboard = () => import("./pages/dashboard");
const projects = () => import("./pages/projects");
const scans = () => import("./pages/scans");
const findings = () => import("./pages/findings");
const org = () => import("./pages/org");
const account = () => import("./pages/account");
const OnboardingPage = lazy(() => dashboard().then((m) => ({ default: m.OnboardingPage })));
const DashboardPage = lazy(() => dashboard().then((m) => ({ default: m.DashboardPage })));
const AnalyticsPage = lazy(() => dashboard().then((m) => ({ default: m.AnalyticsPage })));
const ProjectsPage = lazy(() => projects().then((m) => ({ default: m.ProjectsPage })));
const ProjectDetailPage = lazy(() => projects().then((m) => ({ default: m.ProjectDetailPage })));
const ScansPage = lazy(() => scans().then((m) => ({ default: m.ScansPage })));
const ScanDetailPage = lazy(() => scans().then((m) => ({ default: m.ScanDetailPage })));
const ScanComparePage = lazy(() => scans().then((m) => ({ default: m.ScanComparePage })));
const FindingsPage = lazy(() => findings().then((m) => ({ default: m.FindingsPage })));
const FindingDetailPage = lazy(() => findings().then((m) => ({ default: m.FindingDetailPage })));
const ReviewsPage = lazy(() => findings().then((m) => ({ default: m.ReviewsPage })));
const AuditLogPage = lazy(() => org().then((m) => ({ default: m.AuditLogPage })));
const IntegrationsPage = lazy(() => org().then((m) => ({ default: m.IntegrationsPage })));
const OrgSettingsPage = lazy(() => org().then((m) => ({ default: m.OrgSettingsPage })));
const PolicyPage = lazy(() => org().then((m) => ({ default: m.PolicyPage })));
const ReportsPage = lazy(() => org().then((m) => ({ default: m.ReportsPage })));
const SchedulesPage = lazy(() => org().then((m) => ({ default: m.SchedulesPage })));
const TeamPage = lazy(() => org().then((m) => ({ default: m.TeamPage })));
const AccountSecurityPage = lazy(() => account().then((m) => ({ default: m.AccountSecurityPage })));
const AdminPage = lazy(() => account().then((m) => ({ default: m.AdminPage })));
const NotificationsPage = lazy(() => account().then((m) => ({ default: m.NotificationsPage })));
const ProfilePage = lazy(() => account().then((m) => ({ default: m.ProfilePage })));

function RequireAuth() {
  const { session, loading } = useAuth();
  const location = useLocation();
  if (loading) return <div className="p-8"><Skeleton rows={5} /></div>;
  if (!session) return <Navigate to={`/login?next=${encodeURIComponent(location.pathname + location.search)}`} replace />;
  return <Suspense fallback={<div className="p-8"><Skeleton rows={5} /></div>}><Outlet /></Suspense>;
}

function RequireOrg() {
  const { orgId } = useParams();
  const { session } = useAuth();
  const org = session?.organizations.find((item) => item.id === orgId);
  if (!org) {
    return (
      <div className="mx-auto max-w-lg py-16 text-center">
        <h1 className="text-lg font-semibold">Organization not found</h1>
        <p className="mt-2 text-[13px] text-muted">It doesn't exist or you are not a member.</p>
        <div className="mt-4"><ButtonLink to="/onboarding" variant="primary">Choose an organization</ButtonLink></div>
      </div>
    );
  }
  return <Suspense fallback={<Skeleton rows={6} />}><Outlet key={org.id} /></Suspense>;
}

function RequirePlatformAdmin() {
  const { session } = useAuth();
  return session?.user.is_platform_admin ? <Outlet /> : <Navigate to="/" replace />;
}

class ErrorBoundary extends Component<{ children: ReactNode }, { error: unknown }> {
  state = { error: null as unknown };
  static getDerivedStateFromError(error: unknown) { return { error }; }
  render() {
    if (this.state.error) return <div className="p-8"><ErrorState error={this.state.error} retry={() => this.setState({ error: null })} /></div>;
    return this.props.children;
  }
}

export default function App() {
  return (
    <ErrorBoundary>
      <Routes>
        <Route path="/" element={<LandingPage />} />
        <Route path="/login" element={<LoginPage />} />
        <Route path="/register" element={<RegisterPage />} />
        <Route path="/forgot-password" element={<ForgotPasswordPage />} />
        <Route path="/reset-password" element={<ResetPasswordPage />} />
        <Route path="/verify-email" element={<VerifyEmailPage />} />
        <Route path="/invitations/accept" element={<AcceptInvitationPage />} />
        <Route element={<RequireAuth />}>
          <Route element={<AppShell />}>
            <Route path="/onboarding" element={<OnboardingPage />} />
            <Route path="/notifications" element={<NotificationsPage />} />
            <Route path="/account" element={<ProfilePage />} />
            <Route path="/account/security" element={<AccountSecurityPage />} />
            <Route element={<RequirePlatformAdmin />}><Route path="/admin" element={<AdminPage />} /></Route>
            <Route path="/orgs/:orgId" element={<RequireOrg />}>
              <Route index element={<Navigate to="dashboard" replace />} />
              <Route path="dashboard" element={<DashboardPage />} />
              <Route path="projects" element={<ProjectsPage />} />
              <Route path="projects/:projectId" element={<ProjectDetailPage />} />
              <Route path="scans" element={<ScansPage />} />
              <Route path="scans/:scanId" element={<ScanDetailPage />} />
              <Route path="scans/:scanId/compare/:otherId" element={<ScanComparePage />} />
              <Route path="findings" element={<FindingsPage />} />
              <Route path="findings/:findingId" element={<FindingDetailPage />} />
              <Route path="remediation" element={<FindingsPage mine />} />
              <Route path="reviews" element={<ReviewsPage />} />
              <Route path="analytics" element={<AnalyticsPage />} />
              <Route path="reports" element={<ReportsPage />} />
              <Route path="audit" element={<AuditLogPage />} />
              <Route path="policy" element={<PolicyPage />} />
              <Route path="schedules" element={<SchedulesPage />} />
              <Route path="integrations" element={<IntegrationsPage />} />
              <Route path="team" element={<TeamPage />} />
              <Route path="settings" element={<OrgSettingsPage />} />
            </Route>
          </Route>
        </Route>
        <Route path="*" element={<div className="mx-auto max-w-lg py-24 text-center"><h1 className="text-lg font-semibold">Page not found</h1><div className="mt-4"><ButtonLink to="/">Go home</ButtonLink></div></div>} />
      </Routes>
    </ErrorBoundary>
  );
}
