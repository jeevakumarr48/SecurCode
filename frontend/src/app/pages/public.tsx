import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { Link, Navigate, useNavigate, useSearchParams } from "react-router";
import { api, errorMessage, setCsrfToken } from "../lib/api";
import { useAuth } from "../lib/auth";
import type { SessionPayload } from "../lib/types";
import { Logo, ThemeToggle } from "../components/Shell";
import { Button, ButtonLink, Notice, TextInput } from "../components/ui";

function AuthCard({ title, children, footer }: { title: string; children: ReactNode; footer?: ReactNode }) {
  return (
    <div className="flex min-h-screen flex-col bg-bg">
      <header className="flex h-14 items-center justify-between border-b border-line px-5">
        <Link to="/"><Logo /></Link>
        <ThemeToggle />
      </header>
      <main id="main" className="flex flex-1 items-start justify-center px-4 py-12">
        <div className="w-full max-w-sm">
          <h1 className="mb-5 text-xl font-semibold text-fg">{title}</h1>
          <div className="space-y-4 border border-line bg-surface p-5">{children}</div>
          {footer && <div className="mt-4 text-center text-[13px] text-muted">{footer}</div>}
        </div>
      </main>
    </div>
  );
}

export function landingTarget(session: SessionPayload | null) {
  if (!session) return null;
  if (session.active_org_id) return `/orgs/${session.active_org_id}/dashboard`;
  return "/onboarding";
}

const capabilities = [
  ["Multi-tenant by design", "Organizations, six roles and per-project access, enforced on every API request with tenant-scoped queries."],
  ["Static analysis you can audit", "45 rules: Python AST checks with bounded intra-file taint tracking, plus JavaScript/TypeScript rules on comment-masked source."],
  ["Isolated scanning", "Uploaded archives and repositories are extracted defensively and analysed in a resource-limited worker process. Code is never executed."],
  ["Vulnerability lifecycle", "Triage, assignment, comments, reviewed risk acceptance and false positives. Fixes count as verified only after a complete rescan."],
  ["GitHub workflow", "Scan branches and commits, receive signed webhooks, and post pull-request summaries that list only newly introduced findings."],
  ["Evidence for audits", "SARIF 2.1.0, CSV and JSON exports, printable reports, and a hash-chained audit trail of security-relevant actions."],
];

export function LandingPage() {
  const { session, loading } = useAuth();
  const target = landingTarget(session);
  return (
    <div className="min-h-screen bg-bg">
      <header className="flex h-14 items-center justify-between border-b border-line px-5">
        <Logo />
        <nav className="flex items-center gap-2">
          <a className="px-2 text-[13px] text-muted hover:text-fg" href="#how">How it works</a>
          <a className="px-2 text-[13px] text-muted hover:text-fg" href="#limits">Limitations</a>
          <ThemeToggle />
          {!loading && (target ? <ButtonLink to={target} variant="primary">Open console</ButtonLink> : <>
            <ButtonLink to="/login" variant="ghost">Sign in</ButtonLink>
            <ButtonLink to="/register" variant="primary">Create account</ButtonLink>
          </>)}
        </nav>
      </header>
      <main id="main">
        <section className="mx-auto max-w-5xl px-6 py-20">
          <p className="mb-3 text-xs font-medium uppercase tracking-widest text-accent">Application security platform</p>
          <h1 className="max-w-3xl text-4xl font-semibold leading-tight tracking-tight text-fg sm:text-5xl">Find, prioritise and verify fixes for vulnerabilities in your source code, as a team.</h1>
          <p className="mt-5 max-w-2xl text-base text-muted">SecurCode scans Python, JavaScript and TypeScript, tracks every finding through triage and remediation, and only marks a fix as verified after a complete rescan stops detecting it.</p>
          <div className="mt-8 flex flex-wrap gap-3">
            <ButtonLink to="/register" variant="primary">Start with a free account</ButtonLink>
            <a href="https://github.com/jeevakumarr48/SecurCode" className="inline-flex items-center rounded-[3px] border border-line px-3 py-1.5 text-[13px] text-fg hover:border-accent">Read the source &amp; docs</a>
          </div>
        </section>
        <section className="border-y border-line bg-surface">
          <div className="mx-auto grid max-w-5xl gap-px bg-line sm:grid-cols-2 lg:grid-cols-3">
            {capabilities.map(([title, body]) => (
              <div key={title} className="bg-surface p-6"><h2 className="text-sm font-semibold text-fg">{title}</h2><p className="mt-2 text-[13px] text-muted">{body}</p></div>
            ))}
          </div>
        </section>
        <section id="how" className="mx-auto max-w-5xl px-6 py-16">
          <h2 className="text-lg font-semibold text-fg">How a scan works</h2>
          <ol className="mt-6 grid gap-6 sm:grid-cols-4">
            {[["1. Connect", "Upload a .zip/.tar.gz or connect a GitHub repository with a read-only token."],
              ["2. Queue", "The API records the scan and returns immediately. A separate worker claims it."],
              ["3. Analyse", "The source is unpacked into an isolated workspace. The worker reads it as text and never runs it."],
              ["4. Reconcile", "Findings are fingerprinted, deduplicated and compared with earlier scans: new, recurring, or verified fixed."]].map(([t, b]) => (
              <li key={t} className="border-t border-accent/50 pt-3"><div className="text-[13px] font-semibold text-fg">{t}</div><p className="mt-1 text-[13px] text-muted">{b}</p></li>
            ))}
          </ol>
          <h2 className="mt-14 text-lg font-semibold text-fg">Supported languages</h2>
          <p className="mt-2 text-[13px] text-muted">Python (AST rules and bounded intra-file taint analysis) · JavaScript, JSX, TypeScript, TSX (lexical rules on comment- and string-masked source) · SARIF 2.1.0 import from other tools.</p>
        </section>
        <section id="limits" className="border-t border-line bg-surface">
          <div className="mx-auto max-w-5xl px-6 py-12">
            <h2 className="text-lg font-semibold text-fg">Honest limitations</h2>
            <ul className="mt-4 list-disc space-y-1 pl-5 text-[13px] text-muted">
              <li>No cross-file or interprocedural data-flow analysis, dependency (SCA) scanning, or runtime testing.</li>
              <li>JavaScript/TypeScript rules are lexical. They cannot follow values through aliases or across files.</li>
              <li>The posture score is an internal prioritisation signal, not a certification or a measure of total security.</li>
              <li>Benchmark figures come from small curated fixtures and do not predict accuracy on real-world code.</li>
            </ul>
          </div>
        </section>
      </main>
      <footer className="px-6 py-8 text-center text-xs text-faint">SecurCode · <Link to="/legacy.html" reloadDocument className="underline">Legacy console</Link></footer>
    </div>
  );
}

export function LoginPage() {
  const { session, setSession } = useAuth();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [mfa, setMfa] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const next = params.get("next");
  const safeNext = next && next.startsWith("/") && !next.startsWith("//") ? next : null;

  if (session && !mfa) return <Navigate to={safeNext ?? landingTarget(session) ?? "/onboarding"} replace />;

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      if (mfa) {
        const payload = await api.post<SessionPayload & { status: string }>("/auth/mfa/verify", { code });
        setSession(payload);
        navigate(safeNext ?? landingTarget(payload) ?? "/onboarding");
        return;
      }
      const payload = await api.post<SessionPayload & { status: string }>("/auth/login", { email, password });
      if (payload.status === "mfa_required") {
        // The pending-MFA session has its own CSRF token for the challenge.
        setCsrfToken(payload.csrf_token);
        setMfa(true);
        return;
      }
      setSession(payload);
      navigate(safeNext ?? landingTarget(payload) ?? "/onboarding");
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthCard title={mfa ? "Two-factor verification" : "Sign in to SecurCode"} footer={<>New here? <Link className="text-accent" to="/register">Create an account</Link></>}>
      <form className="space-y-4" onSubmit={submit} noValidate>
        {error && <Notice tone="error">{error}</Notice>}
        {mfa ? (
          <TextInput label="6-digit code from your authenticator app" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" maxLength={6} value={code} onChange={(e) => setCode(e.target.value)} required autoFocus />
        ) : (
          <>
            <TextInput label="Email" type="email" autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} required autoFocus />
            <TextInput label="Password" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required />
          </>
        )}
        <Button type="submit" variant="primary" className="w-full" busy={busy}>{mfa ? "Verify" : "Sign in"}</Button>
        {!mfa && <Link to="/forgot-password" className="block text-center text-xs text-muted hover:text-fg">Forgot your password?</Link>}
      </form>
    </AuthCard>
  );
}

export function RegisterPage() {
  const { session, setSession } = useAuth();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const [form, setForm] = useState({ email: params.get("email") ?? "", password: "", display_name: "" });
  const [error, setError] = useState<string | null>(null);
  const [verifyLink, setVerifyLink] = useState<string | null | undefined>(undefined);
  const [busy, setBusy] = useState(false);
  const next = params.get("next");
  if (session) return <Navigate to={next?.startsWith("/") ? next : landingTarget(session) ?? "/onboarding"} replace />;

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const payload = await api.post<SessionPayload & { status: string; development_verification_link?: string | null }>("/auth/register", form);
      if (payload.status === "verification_required") {
        setVerifyLink(payload.development_verification_link ?? null);
        return;
      }
      setSession(payload);
      navigate(next?.startsWith("/") && !next.startsWith("//") ? next : "/onboarding");
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  if (verifyLink !== undefined) {
    return (
      <AuthCard title="Check your email">
        <p className="text-[13px] text-muted">We sent a verification link to {form.email}. Open it to activate your account.</p>
        {verifyLink && <Notice tone="warning">Development mode, no email provider is configured: <a className="underline" href={verifyLink}>open the verification link</a>.</Notice>}
      </AuthCard>
    );
  }
  return (
    <AuthCard title="Create your account" footer={<>Already registered? <Link className="text-accent" to="/login">Sign in</Link></>}>
      <form className="space-y-4" onSubmit={submit} noValidate>
        {error && <Notice tone="error">{error}</Notice>}
        <TextInput label="Name" autoComplete="name" value={form.display_name} onChange={(e) => setForm({ ...form, display_name: e.target.value })} />
        <TextInput label="Work email" type="email" autoComplete="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} required />
        <TextInput label="Password" type="password" autoComplete="new-password" minLength={12} hint="At least 12 characters. Long passphrases are best." value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} required />
        <Button type="submit" variant="primary" className="w-full" busy={busy}>Create account</Button>
      </form>
    </AuthCard>
  );
}

export function ForgotPasswordPage() {
  const [email, setEmail] = useState("");
  const [sent, setSent] = useState<{ link: string | null } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  return (
    <AuthCard title="Reset your password" footer={<Link className="text-accent" to="/login">Back to sign in</Link>}>
      {sent ? (
        <div className="space-y-3 text-[13px] text-muted">
          <p>If an account exists for {email}, a reset link valid for 30 minutes is on its way.</p>
          {sent.link && <Notice tone="warning">Development mode: <a className="underline" href={sent.link}>open the reset link</a>.</Notice>}
        </div>
      ) : (
        <form className="space-y-4" onSubmit={async (event) => {
          event.preventDefault(); setBusy(true); setError(null);
          try { const r = await api.post<{ development_reset_link: string | null }>("/auth/password/forgot", { email }); setSent({ link: r.development_reset_link }); }
          catch (err) { setError(errorMessage(err)); } finally { setBusy(false); }
        }}>
          {error && <Notice tone="error">{error}</Notice>}
          <TextInput label="Email" type="email" autoComplete="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
          <Button type="submit" variant="primary" className="w-full" busy={busy}>Send reset link</Button>
        </form>
      )}
    </AuthCard>
  );
}

export function ResetPasswordPage() {
  const [params] = useSearchParams();
  const token = params.get("token") ?? "";
  const [password, setPassword] = useState("");
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    // Remove the token from the address bar and history once read.
    if (token) window.history.replaceState(null, "", "/reset-password");
  }, [token]);
  return (
    <AuthCard title="Choose a new password">
      {done ? (
        <div className="space-y-3"><Notice tone="ok">Password updated. All existing sessions were signed out.</Notice><ButtonLink to="/login" variant="primary">Sign in</ButtonLink></div>
      ) : !token ? <Notice tone="error">This reset link is incomplete. Request a new one.</Notice> : (
        <form className="space-y-4" onSubmit={async (event) => {
          event.preventDefault(); setBusy(true); setError(null);
          try { await api.post("/auth/password/reset", { token, new_password: password }); setDone(true); }
          catch (err) { setError(errorMessage(err)); } finally { setBusy(false); }
        }}>
          {error && <Notice tone="error">{error}</Notice>}
          <TextInput label="New password" type="password" autoComplete="new-password" minLength={12} value={password} onChange={(e) => setPassword(e.target.value)} required />
          <Button type="submit" variant="primary" className="w-full" busy={busy}>Update password</Button>
        </form>
      )}
    </AuthCard>
  );
}

export function VerifyEmailPage() {
  const [params] = useSearchParams();
  const [state, setState] = useState<"working" | "ok" | string>("working");
  useEffect(() => {
    const token = params.get("token");
    if (!token) { setState("This verification link is incomplete."); return; }
    window.history.replaceState(null, "", "/verify-email");
    api.post("/auth/verify-email", { token }).then(() => setState("ok")).catch((err) => setState(errorMessage(err)));
  }, [params]);
  return (
    <AuthCard title="Email verification">
      {state === "working" && <p className="text-[13px] text-muted">Verifying…</p>}
      {state === "ok" && <><Notice tone="ok">Your email address is verified.</Notice><ButtonLink to="/login" variant="primary">Sign in</ButtonLink></>}
      {state !== "working" && state !== "ok" && <Notice tone="error">{state}</Notice>}
    </AuthCard>
  );
}

export function AcceptInvitationPage() {
  const [params] = useSearchParams();
  const { session, setSession, refresh } = useAuth();
  const navigate = useNavigate();
  const [token] = useState(() => params.get("token") ?? sessionStorage.getItem("securcode-invite") ?? "");
  const [preview, setPreview] = useState<{ organization_name: string; role: string; email: string; has_account: boolean } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (!token) { setError("This invitation link is incomplete."); return; }
    // Keep the token only for this tab while the invitee signs in or registers.
    sessionStorage.setItem("securcode-invite", token);
    window.history.replaceState(null, "", "/invitations/accept");
    api.post<typeof preview>("/invitations/preview", { token }).then(setPreview).catch((err) => setError(errorMessage(err)));
  }, [token]);

  async function accept() {
    setBusy(true); setError(null);
    try {
      const result = await api.post<{ org_id: string }>("/invitations/accept", { token });
      sessionStorage.removeItem("securcode-invite");
      const payload = await refresh();
      if (payload) setSession(payload);
      navigate(`/orgs/${result.org_id}/dashboard`);
    } catch (err) { setError(errorMessage(err)); } finally { setBusy(false); }
  }

  return (
    <AuthCard title="Organization invitation">
      {error && <Notice tone="error">{error}</Notice>}
      {preview && (
        <div className="space-y-4 text-[13px]">
          <p className="text-muted">You have been invited to join <strong className="text-fg">{preview.organization_name}</strong> as <strong className="text-fg">{preview.role.replaceAll("_", " ")}</strong>.</p>
          {session ? (
            session.user.email === preview.email
              ? <Button variant="primary" className="w-full" busy={busy} onClick={accept}>Accept and join</Button>
              : <Notice tone="warning">This invitation is for {preview.email}, but you are signed in as {session.user.email}. Sign out and sign in with the invited address.</Notice>
          ) : preview.has_account ? (
            <ButtonLink variant="primary" className="w-full" to={`/login?next=${encodeURIComponent("/invitations/accept")}`}>Sign in as {preview.email}</ButtonLink>
          ) : (
            <ButtonLink variant="primary" className="w-full" to={`/register?email=${encodeURIComponent(preview.email)}&next=${encodeURIComponent("/invitations/accept")}`}>Create an account for {preview.email}</ButtonLink>
          )}
        </div>
      )}
    </AuthCard>
  );
}
