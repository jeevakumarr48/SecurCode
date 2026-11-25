export type Role = "owner" | "admin" | "security_admin" | "security_analyst" | "developer" | "viewer";
export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type FindingStatus = "open" | "triaged" | "in_progress" | "fixed" | "resolved" | "accepted_risk" | "false_positive" | "reopened";
export type ScanStatus = "queued" | "running" | "completed" | "completed_with_warnings" | "failed" | "cancelled";

export interface OrgSummary {
  id: string;
  name: string;
  slug: string;
  status: string;
  role: Role;
  is_demo: boolean;
  permissions: string[];
}

export interface SessionPayload {
  user: { id: string; email: string; display_name: string; email_verified: boolean; mfa_enabled: boolean; is_platform_admin: boolean; created_at: string };
  organizations: OrgSummary[];
  active_org_id: string | null;
  csrf_token: string | null;
}

export interface Page<T> { items: T[]; total: number; limit: number; offset: number }

export interface Posture { score: number | null; grade: string | null; assessed: boolean; risk_points: number | null; formula: string; reason?: string; last_scan_age_days?: number }

export interface Project {
  id: string; org_id: string; name: string; slug: string; description: string; status: "active" | "archived";
  source_type: "upload" | "github" | "fixture"; repository_full_name: string | null; repository_url: string | null;
  default_branch: string; fixture_name: string | null; languages: string[]; owner_id: string | null;
  created_at: string; updated_at: string; last_scan_at: string | null;
  last_scan: { id: string; status: ScanStatus; created_at: string } | null;
  active_findings: { total: number } & Partial<Record<Severity, number>>;
  posture: Posture;
  members?: { user_id: string; email: string; display_name: string; role: string }[];
}

export interface Scan {
  id: string; org_id: string; project_id: string; project_name?: string; status: ScanStatus; trigger: string; source_type: string;
  branch: string | null; commit_sha: string | null; pull_request_number: number | null; scope_key: string;
  progress: number; progress_message: string; scanner_version: string | null; ruleset_version: string | null; rule_count: number;
  files_scanned: number; warnings: { path: string; message: string }[];
  summary: { total?: number; new?: number; resolved?: number; reopened?: number; by_severity?: Partial<Record<Severity, number>>; not_verified_due_to_partial_scan?: number; filtered_by_policy?: number };
  error_message: string | null; cancel_requested: boolean; created_at: string; started_at: string | null; finished_at: string | null;
  duration_ms: number | null; is_clean: boolean; logs?: { at: string; level: string; message: string }[];
}

export interface Finding {
  id: string; org_id: string; project_id: string; project_name?: string; scope: string; rule_id: string; title: string; description: string;
  severity: Severity; original_severity: Severity; confidence: string; language: string | null; cwe: string | null; owasp: string | null;
  file_path: string; line: number | null; status: FindingStatus; verification_status: string;
  assignee: { id: string; email: string; display_name: string } | null; assignee_id: string | null;
  due_date: string | null; overdue: boolean; labels: string[]; first_detected_at: string; last_detected_at: string;
  first_scan_id: string | null; last_scan_id: string | null; fixed_scan_id: string | null; recurrence_count: number; fingerprint: string;
}

export interface FindingDetail extends Finding {
  snippet: string | null; remediation_notes: string | null;
  guidance: { meaning?: string; why_it_matters?: string; where?: string; recommended_fix?: string; safer_example?: string | null;
    validation_steps?: string[]; cwe?: string | null; cwe_url?: string | null; owasp?: string | null; detection_technique?: string;
    false_positive_considerations?: string | null; references?: string[]; summary?: string };
  ai_assistance: { available: boolean; reason: string };
  events: { id: string; kind: string; body: string | null; from: string | null; to: string | null; actor: string; created_at: string }[];
  reviews: Review[];
  allowed_transitions: FindingStatus[];
}

export interface Review {
  id: string; finding_id: string; kind: "accepted_risk" | "false_positive"; status: string; justification: string; reviewer_note: string | null;
  requested_by: string | null; reviewer: string | null; expires_at: string | null; created_at: string; reviewed_at: string | null;
  finding_title?: string; severity?: Severity;
}

export interface Member { membership_id: string; user_id: string; email: string; display_name: string; role: Role; is_active: boolean; joined_at: string }
export interface Invitation { id: string; email: string; role: Role; state: string; expires_at: string; created_at: string; send_count: number; accept_link?: string; delivery?: string }

export interface Notification { id: string; kind: string; title: string; body: string; link: string | null; org_id: string | null; read: boolean; created_at: string }

export interface Dashboard {
  generated_at: string; is_demo: boolean; window_days: number;
  totals: Record<"projects" | "scans" | "active_findings" | Severity | "new_findings" | "resolved_findings" | "recurring_findings" | "open_remediation_tasks" | "overdue", number>;
  scan_health: { success_rate: number | null; average_duration_ms: number | null; running: number; queued: number; failed: number };
  status_breakdown: Partial<Record<FindingStatus, number>>;
  remediation_progress: { remediated: number; total: number; ratio: number | null };
  posture: { score: number | null; grade: string | null; formula: string; projects: (Posture & { project_id: string; name: string; active_findings: number })[] };
  trend: { date: string; open: number; new: number }[];
  distribution: { cwe: { name: string; count: number }[]; owasp: { name: string; count: number }[]; language: { name: string; count: number }[] };
}

export interface Comparison {
  base_scan: { id: string; created_at: string; status: string; scanner_version: string; ruleset_version: string; scope: string; commit_sha: string | null; files_scanned: number };
  head_scan: Comparison["base_scan"];
  equivalent: boolean; warnings: string[];
  summary: Record<"new" | "resolved" | "recurring" | "unchanged" | "severity_changes" | "confidence_changes" | "no_longer_in_rule_scope", number>;
  rule_coverage: { added: string[]; removed: string[] };
  new: CompareItem[]; resolved: CompareItem[]; recurring: CompareItem[]; unchanged: CompareItem[];
  severity_changes: (CompareItem & { from: string; to: string })[];
  no_longer_in_rule_scope: CompareItem[];
}
export interface CompareItem { finding_id: string; rule_id: string; title: string; severity: Severity; confidence: string; file_path: string; line: number | null; current_status: FindingStatus }

export interface Integration { id: string; provider: string; account_login: string | null; status: string; credential_hint: string | null; last_error: string | null;
  settings: Record<string, unknown>; webhook_url: string; created_at: string; webhook_secret?: string }

export interface AuditEvent { id: number; action: string; actor_email: string | null; project_id: string | null; resource_type: string | null; resource_id: string | null;
  metadata: Record<string, unknown>; ip_address: string | null; request_id: string | null; created_at: string; hash: string }

export interface Schedule { id: string; project_id: string; frequency: "daily" | "weekly"; hour: number; minute: number; weekday: number | null; timezone: string;
  branch: string | null; enabled: boolean; next_run_at: string | null; last_run_at: string | null; last_error: string | null;
  history: { scan_id: string; status: ScanStatus; created_at: string }[] }

export interface Policy { version: number; config: PolicyConfig; updated_at: string; can_edit: boolean }
export interface PolicyConfig {
  disabled_rules: Record<string, string>; minimum_severity: Severity; minimum_confidence: string; excluded_paths: string[];
  max_file_bytes: number; max_archive_bytes: number; max_scan_seconds: number; pr_fail_severity: Severity | null;
  accepted_risk_max_days: number; false_positive_requires_review: boolean; accepted_risk_requires_review: boolean;
  default_due_days: Partial<Record<Severity, number>>;
}

export interface Rule { id: string; name: string; description: string; severity: Severity; confidence: string; cwe: string | null; owasp: string | null; languages: string[]; technique: string }
