import { useEffect, useId, useRef, type ButtonHTMLAttributes, type InputHTMLAttributes, type ReactNode, type SelectHTMLAttributes, type TextareaHTMLAttributes } from "react";
import { Link } from "react-router";
import { errorMessage } from "../lib/api";
import type { FindingStatus, ScanStatus, Severity } from "../lib/types";

export function cx(...classes: (string | false | null | undefined)[]) {
  return classes.filter(Boolean).join(" ");
}

type Variant = "primary" | "secondary" | "ghost" | "danger";
const variants: Record<Variant, string> = {
  primary: "bg-accent text-accent-ink hover:bg-accent-strong border-transparent",
  secondary: "bg-raised text-fg border-line hover:border-accent",
  ghost: "bg-transparent text-muted border-transparent hover:text-fg hover:bg-raised",
  danger: "bg-transparent text-critical border-critical/60 hover:bg-critical-soft",
};

export function Button({ variant = "secondary", busy, className, children, disabled, ...props }: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant; busy?: boolean }) {
  return (
    <button
      type="button"
      {...props}
      disabled={disabled || busy}
      aria-busy={busy || undefined}
      className={cx("inline-flex items-center justify-center gap-2 rounded-[3px] border px-3 py-1.5 text-[13px] font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50", variants[variant], className)}
    >
      {busy && <span className="h-3 w-3 animate-spin rounded-full border-2 border-current border-t-transparent" aria-hidden />}
      {children}
    </button>
  );
}

export function ButtonLink({ to, children, variant = "secondary", className }: { to: string; children: ReactNode; variant?: Variant; className?: string }) {
  return <Link to={to} className={cx("inline-flex items-center justify-center gap-2 rounded-[3px] border px-3 py-1.5 text-[13px] font-medium", variants[variant], className)}>{children}</Link>;
}

const fieldClass = "w-full rounded-[3px] border border-line bg-inset px-2.5 py-1.5 text-[13px] text-fg placeholder:text-faint focus:border-accent focus:outline-none";

export function Field({ label, hint, error, children, id }: { label: string; hint?: string; error?: string; children: ReactNode; id: string }) {
  return (
    <div className="space-y-1">
      <label htmlFor={id} className="block text-xs font-medium text-muted">{label}</label>
      {children}
      {hint && !error && <p className="text-xs text-faint" id={`${id}-hint`}>{hint}</p>}
      {error && <p className="text-xs text-critical" role="alert">{error}</p>}
    </div>
  );
}

export function TextInput({ label, hint, error, ...props }: InputHTMLAttributes<HTMLInputElement> & { label: string; hint?: string; error?: string }) {
  const id = useId();
  return <Field id={id} label={label} hint={hint} error={error}><input id={id} aria-describedby={hint ? `${id}-hint` : undefined} aria-invalid={error ? true : undefined} className={fieldClass} {...props} /></Field>;
}

export function TextArea({ label, hint, ...props }: TextareaHTMLAttributes<HTMLTextAreaElement> & { label: string; hint?: string }) {
  const id = useId();
  return <Field id={id} label={label} hint={hint}><textarea id={id} className={cx(fieldClass, "min-h-20")} {...props} /></Field>;
}

export function Select({ label, options, hint, ...props }: SelectHTMLAttributes<HTMLSelectElement> & { label: string; hint?: string; options: { value: string; label: string }[] }) {
  const id = useId();
  return (
    <Field id={id} label={label} hint={hint}>
      <select id={id} className={fieldClass} {...props}>
        {options.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
      </select>
    </Field>
  );
}

export function Checkbox({ label, checked, onChange, disabled }: { label: string; checked: boolean; onChange: (value: boolean) => void; disabled?: boolean }) {
  const id = useId();
  return (
    <label htmlFor={id} className="inline-flex cursor-pointer items-center gap-2 text-[13px] text-fg">
      <input id={id} type="checkbox" className="h-3.5 w-3.5 accent-[var(--accent)]" checked={checked} disabled={disabled} onChange={(event) => onChange(event.target.checked)} />
      {label}
    </label>
  );
}

const severityStyle: Record<Severity, string> = {
  critical: "text-critical bg-critical-soft border-critical/40",
  high: "text-high bg-high-soft border-high/40",
  medium: "text-medium bg-medium-soft border-medium/40",
  low: "text-low bg-low-soft border-low/40",
  info: "text-muted bg-raised border-line",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={cx("inline-flex min-w-16 justify-center rounded-[2px] border px-1.5 py-px text-[11px] font-semibold uppercase tracking-wide", severityStyle[severity])}>{severity}</span>;
}

const statusTone: Record<string, string> = {
  open: "text-fg border-line", triaged: "text-accent border-accent/40", in_progress: "text-medium border-medium/40",
  fixed: "text-ok border-ok/40", resolved: "text-ok border-ok/40 bg-ok-soft", accepted_risk: "text-muted border-line",
  false_positive: "text-muted border-line", reopened: "text-critical border-critical/40",
  queued: "text-muted border-line", running: "text-accent border-accent/40", completed: "text-ok border-ok/40",
  completed_with_warnings: "text-medium border-medium/40", failed: "text-critical border-critical/40", cancelled: "text-muted border-line",
  active: "text-ok border-ok/40", archived: "text-muted border-line", pending: "text-medium border-medium/40",
  approved: "text-ok border-ok/40", rejected: "text-critical border-critical/40", expired: "text-muted border-line",
  error: "text-critical border-critical/40", revoked: "text-muted border-line",
};

export function StatusBadge({ status }: { status: FindingStatus | ScanStatus | string }) {
  return <span className={cx("inline-flex items-center gap-1 whitespace-nowrap rounded-[2px] border px-1.5 py-px text-[11px] font-medium", statusTone[status] ?? "text-muted border-line")}>{status === "running" && <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-accent" aria-hidden />}{status.replaceAll("_", " ")}</span>;
}

export function PageHeader({ title, description, actions, eyebrow }: { title: string; description?: ReactNode; actions?: ReactNode; eyebrow?: ReactNode }) {
  return (
    <header className="mb-6 flex flex-wrap items-end justify-between gap-4 border-b border-line pb-4">
      <div className="min-w-0">
        {eyebrow && <div className="mb-1 text-xs text-faint">{eyebrow}</div>}
        <h1 className="text-xl font-semibold tracking-tight text-fg">{title}</h1>
        {description && <p className="mt-1 max-w-3xl text-[13px] text-muted">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </header>
  );
}

export function Section({ title, actions, children, className }: { title?: string; actions?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={cx("border-t border-line pt-4", className)}>
      {(title || actions) && (
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          {title && <h2 className="text-sm font-semibold text-fg">{title}</h2>}
          {actions}
        </div>
      )}
      {children}
    </section>
  );
}

export function Stat({ label, value, tone, hint }: { label: string; value: ReactNode; tone?: Severity | "ok"; hint?: string }) {
  const toneClass = tone === "ok" ? "text-ok" : tone ? severityStyle[tone].split(" ")[0] : "text-fg";
  return (
    <div className="border-l border-line pl-3">
      <div className="text-xs text-muted">{label}</div>
      <div className={cx("tabular text-2xl font-semibold", toneClass)}>{value}</div>
      {hint && <div className="text-[11px] text-faint">{hint}</div>}
    </div>
  );
}

export function Skeleton({ rows = 4 }: { rows?: number }) {
  return (
    <div className="space-y-2" role="status" aria-label="Loading">
      {Array.from({ length: rows }, (_, index) => <div key={index} className="h-4 animate-pulse rounded-sm bg-raised" style={{ width: `${90 - index * 9}%` }} />)}
    </div>
  );
}

export function EmptyState({ title, children, action }: { title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="border border-dashed border-line px-6 py-10 text-center">
      <p className="text-sm font-medium text-fg">{title}</p>
      {children && <p className="mx-auto mt-1 max-w-lg text-[13px] text-muted">{children}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

export function ErrorState({ error, retry }: { error: unknown; retry?: () => void }) {
  return (
    <div role="alert" className="flex flex-wrap items-center justify-between gap-3 border border-critical/40 bg-critical-soft px-4 py-3 text-[13px] text-critical">
      <span>{errorMessage(error)}</span>
      {retry && <Button variant="ghost" onClick={retry}>Try again</Button>}
    </div>
  );
}

export function Notice({ tone = "info", children }: { tone?: "info" | "warning" | "ok" | "error"; children: ReactNode }) {
  const styles = { info: "border-accent/40 bg-accent-soft/40 text-fg", warning: "border-medium/40 bg-medium-soft text-medium", ok: "border-ok/40 bg-ok-soft text-ok", error: "border-critical/40 bg-critical-soft text-critical" };
  return <div role={tone === "error" ? "alert" : "status"} className={cx("border px-3 py-2 text-[13px]", styles[tone])}>{children}</div>;
}

export function Table({ head, children, empty }: { head: ReactNode[]; children: ReactNode; empty?: boolean }) {
  return (
    <div className="overflow-x-auto border border-line">
      <table className="w-full min-w-[640px] border-collapse text-left text-[13px]">
        <thead className="bg-raised text-xs text-muted">
          <tr>{head.map((cell, index) => <th key={index} scope="col" className="whitespace-nowrap border-b border-line px-3 py-2 font-medium">{cell}</th>)}</tr>
        </thead>
        <tbody className="[&>tr]:border-b [&>tr]:border-line-soft [&>tr:last-child]:border-0 [&_td]:px-3 [&_td]:py-2 [&_td]:align-top">{children}</tbody>
      </table>
      {empty && <div className="px-4 py-6 text-center text-[13px] text-muted">Nothing to show yet.</div>}
    </div>
  );
}

export function Pagination({ total, limit, offset, onChange }: { total: number; limit: number; offset: number; onChange: (offset: number) => void }) {
  if (total <= limit) return null;
  return (
    <nav className="mt-3 flex items-center justify-between text-xs text-muted" aria-label="Pagination">
      <span className="tabular">{offset + 1}–{Math.min(offset + limit, total)} of {total}</span>
      <div className="flex gap-2">
        <Button variant="ghost" disabled={offset === 0} onClick={() => onChange(Math.max(offset - limit, 0))}>Previous</Button>
        <Button variant="ghost" disabled={offset + limit >= total} onClick={() => onChange(offset + limit)}>Next</Button>
      </div>
    </nav>
  );
}

export function ConfirmDialog({ open, title, children, confirmLabel = "Confirm", danger, busy, onConfirm, onCancel, confirmDisabled }: {
  open: boolean; title: string; children: ReactNode; confirmLabel?: string; danger?: boolean; busy?: boolean;
  onConfirm: () => void; onCancel: () => void; confirmDisabled?: boolean;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return;
    if (open && !dialog.open) dialog.showModal?.();
    if (!open && dialog.open) dialog.close?.();
  }, [open]);
  if (!open) return null;
  return (
    <dialog ref={ref} onCancel={onCancel} aria-labelledby="confirm-title" className="m-auto w-[min(480px,92vw)] border border-line bg-surface p-0 text-fg backdrop:bg-black/60">
      <div className="space-y-3 p-5">
        <h2 id="confirm-title" className="text-base font-semibold">{title}</h2>
        <div className="text-[13px] text-muted">{children}</div>
      </div>
      <div className="flex justify-end gap-2 border-t border-line px-5 py-3">
        <Button variant="ghost" onClick={onCancel}>Cancel</Button>
        <Button variant={danger ? "danger" : "primary"} busy={busy} disabled={confirmDisabled} onClick={onConfirm}>{confirmLabel}</Button>
      </div>
    </dialog>
  );
}

export function Tabs<T extends string>({ tabs, value, onChange }: { tabs: { value: T; label: string }[]; value: T; onChange: (value: T) => void }) {
  return (
    <div role="tablist" className="mb-4 flex gap-1 overflow-x-auto border-b border-line">
      {tabs.map((tab) => (
        <button key={tab.value} role="tab" type="button" aria-selected={value === tab.value} onClick={() => onChange(tab.value)}
          className={cx("-mb-px whitespace-nowrap border-b-2 px-3 py-2 text-[13px]", value === tab.value ? "border-accent text-fg" : "border-transparent text-muted hover:text-fg")}>
          {tab.label}
        </button>
      ))}
    </div>
  );
}

export function Mono({ children, className }: { children: ReactNode; className?: string }) {
  return <code className={cx("font-mono text-[12px] text-muted", className)}>{children}</code>;
}

export function DemoBanner({ show }: { show: boolean }) {
  if (!show) return null;
  return <Notice tone="warning">Demo organization: all projects and findings here are sample data from intentionally vulnerable fixtures.</Notice>;
}
