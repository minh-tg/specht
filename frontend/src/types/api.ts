import type {
  AnalysisState,
  GateEffect,
  ReachabilityState,
  Severity,
  TechnicalState,
} from "@/lib/enums";

export interface ScannerDescriptor {
  name: string;
  version: string;
  finding_kinds: string[];
  scan_types: string[];
  provides_packages: boolean;
  supports_auto_detection: boolean;
}

export interface Project {
  id: string;
  slug: string;
  name: string;
  description: string | null;
  created_at: string;
  updated_at: string;
  /** The signed-in caller's effective role. Present when a person reads a single project. */
  role?: ProjectRole;
  permissions?: ProjectPermissions;
}

export type ProjectRole = "admin" | "manager" | "member";

/** What the caller may do on a project, for showing and hiding controls. The server checks again. */
export interface ProjectPermissions {
  request_waiver: boolean;
  manage_waivers: boolean;
  approve_waivers: boolean;
  manage_members: boolean;
  manage_ci: boolean;
  triage: boolean;
}

export type WaiverStatus = "pending" | "approved" | "rejected" | "withdrawn";

export interface WaiverFindingTarget {
  id: string;
  finding_id: string;
}

/** A waiver with the findings it names. Only approved waivers count in the gate. */
export interface Waiver {
  id: string;
  project_id: string;
  name: string;
  description: string;
  enabled: boolean;
  status: WaiverStatus;
  scope_all: boolean;
  reason: string;
  requested_by?: string;
  /** Display name or email of the requester. Left out for API keys. */
  requested_by_name?: string;
  requested_at?: string;
  decided_by?: string;
  /** Display name or email of the decider. Left out for API keys. */
  decided_by_name?: string;
  decided_at?: string;
  decision_note: string;
  expires_at?: string | null;
  conditions: WaiverCondition[];
  contexts: WaiverContext[];
  targets: WaiverFindingTarget[];
  created_at: string;
  updated_at: string;
}

export interface WaiverCondition {
  id: string;
  field: string;
  operator: string;
  value: string;
}

/** Scopes a waiver to an environment, target, or artifact. Unset ids leave that dimension open. */
export interface WaiverContext {
  id: string;
  environment_id?: string;
  target_id?: string;
  artifact_id?: string;
}

/** One entry in a waiver's audit trail. The actor is absent for system events. */
export interface WaiverEvent {
  id: string;
  waiver_id: string;
  event_type: string;
  actor_id?: string | null;
  /** Display name or email of the actor; "System" for automated actions. Left out for API keys. */
  actor_name?: string;
  created_at: string;
}

export interface ProjectMember {
  project_id: string;
  user_id: string;
  role: ProjectRole;
  created_at: string;
  /** Who the member is. Sent to a signed-in person only, so it can be missing. */
  email?: string;
  display_name?: string;
}

export interface ProjectTeam {
  project_id: string;
  team_id: string;
  team_name: string;
  role: ProjectRole;
}

export interface Team {
  id: string;
  name: string;
  description: string;
  /** Not in the schema. TeamsDirectory renders it, so it stays until the server sends it. */
  created_at?: string;
}

export interface TeamMember {
  team_id: string;
  user_id: string;
  role: "admin" | "member";
  /** Omitted when the person never set one. */
  display_name?: string;
  /** Only sent to global admins and admins of the team. */
  user_email?: string;
}

/** Build information reported by the server on /api/v1/version. */
export interface ServerVersion {
  version: string;
  commit: string;
}

export interface FindingIntel {
  cve_id: string;
  /** Probability of exploitation in the next 30 days, 0 to 1. Null when the feed has no score. */
  epss?: number | null;
  epss_date?: string;
  /** Listed in the CISA catalogue of known exploited vulnerabilities. */
  kev: boolean;
  kev_added?: string;
  sources: string[];
  fetched_at: string;
  /** True when a refresh failed and the served record is past its TTL. */
  stale?: boolean;
}

export interface Finding {
  id: string;
  project_id: string;
  finding_kind: string;
  fingerprint: string;
  current_title: string;
  current_severity: Severity;
  current_score?: number | null;
  state: TechnicalState;
  triage_status?: string;
  analysis_state: AnalysisState;
  gate_effect: GateEffect;
  first_seen_at: string;
  last_seen_at: string;
  created_at?: string;
  updated_at?: string;
  /** Deployment context of the finding's latest observation. Absent when
   * the finding has no linked scan occurrence. */
  context?: FindingContext;
  /** Source-aware fix guidance from the latest observation. */
  remediation?: FindingRemediation;
  /** Exact package, rule, resource, file, or URL when supplied. */
  location?: FindingLocation;
  /** Reviewable remediation proposal built from dimensions + guidance. */
  suggestion?: FindingSuggestion;
  /** Exploit intelligence for the finding's CVE. Absent when no feed knows it. */
  intel?: FindingIntel;
  /** Report that first observed the finding. Absent when unattributed. */
  introduced_by_report_id?: string;
  /** Revision the introducing report scanned. Absent when unattributed. */
  introduced_commit_sha?: string;
}

export interface FindingContext {
  target_name?: string;
  target_kind?: string;
  target_owner?: string;
  environment_name?: string;
  branch?: string;
  commit_sha?: string;
  /** Full URL to the source code at the observed commit. */
  source_link?: string;
}

export interface FindingRemediation {
  summary?: string;
  url?: string;
  /** Scanner whose observation supplied the guidance. */
  source?: string;
  /** True when the source supplied nothing and the section is a label. */
  fallback?: boolean;
}

export interface FindingLocation {
  file?: string;
  start_line?: number;
  end_line?: number;
  resource?: string;
  summary?: string;
}

export interface FindingSuggestion {
  action: string;
  target?: string;
  detail?: string;
  confidence: "low" | "medium" | "high";
  source?: string;
}

export interface PolicyEffective {
  template_name: string | null;
  template_version: number;
  severity_floor: string;
  severity_source: "default" | "template" | "override";
  watcher_gate: string;
  watcher_source: "default" | "template" | "override";
}

/** A shared baseline a project can link. Its definition holds the same keys an override can set. */
export interface PolicyTemplate {
  id: string;
  name: string;
  description: string;
  definition: Record<string, string>;
  version: number;
}

export interface GateStatus {
  threshold_breached: boolean;
  blocking_count: number;
  blocked_by?: string[];
  blocked_by_reachability?: Record<string, ReachabilityState>;
  waived_count?: number;
  /** IDs of the blocking findings an active waiver silences. */
  waived_finding_ids?: string[];
  policy?: PolicyEffective;
}

export interface ReachabilityAssessment {
  id: string;
  finding_id: string;
  state: ReachabilityState;
  evidence: string;
  assessed_by: string;
  created_at: string;
  updated_at: string;
}

/** An evidence artifact attached to a finding. `uploaded_by` is null for system-attached evidence. */
export interface FindingEvidence {
  id: string;
  finding_id: string;
  type: string;
  url: string;
  description: string;
  uploaded_by: string | null;
  created_at: string;
}

/** A reviewer's decision on a finding. */
export type SignoffStatus = "pending" | "approved" | "rejected";

/** The reviewer sign-off recorded on a finding. */
export interface Signoff {
  id: string;
  finding_id: string;
  status: SignoffStatus;
  reviewed_by: string;
  comment: string;
  created_at: string;
  updated_at: string;
}

/** One finding lifecycle audit event. */
export interface FindingEvent {
  id: string;
  finding_id: string;
  user_id: string;
  /** Display name or email of whoever did it; "System" for automated actions. Left out for API keys. */
  user_name?: string;
  event_type: string;
  old_value?: string;
  new_value?: string;
  comment?: string;
  /** Base64-encoded JSON with the structured detail of the change. */
  changes?: string;
  created_at: string;
}

export interface RegisterResponse {
  token: string;
  refresh_token: string;
  user_id: string;
  email: string;
}

export interface TriageResponse {
  finding_id: string;
  analysis_state: AnalysisState;
  gate_effect: GateEffect;
}

export interface VerifyResponse {
  finding_id: string;
  outcome: "still_present" | "inconclusive" | "verified_fixed";
  report_id?: string;
  detail: string;
}

export interface LoginResponse {
  token: string;
  refresh_token: string;
  user_id: string;
  email: string;
}

/** What a signed-out page needs to know: which sign-in options exist, and whether the server wants its first admin. */
export interface Capabilities {
  registration: { enabled: boolean; };
  sso: { enabled: boolean; login_path?: string; };
  setup: { required: boolean; };
  version: string;
  commit: string;
}

export type InviteRole = "member" | "manager";

/** An open invite link. `link` is present only in the response to creating it. */
export interface Invite {
  id: string;
  role: InviteRole;
  email?: string;
  created_by?: string;
  created_at: string;
  expires_at: string;
  link?: string;
}

/** What the accept page learns from a link. */
export interface InviteLookup {
  project_name: string;
  role: InviteRole;
  email?: string;
}

/** A new session plus the project it landed in. */
export interface AcceptInviteResponse extends LoginResponse {
  project_slug: string;
  role: ProjectRole;
}

export interface JoinInviteResponse {
  project_slug: string;
  role: ProjectRole;
}

export interface ApiKey {
  id: string;
  name: string;
  key_prefix: string;
  /** The secret. Present only in the creation response. */
  raw_key?: string;
  last_four?: string | null;
  created_at: string;
  expires_at?: string | null;
}

/** The creation response always carries the secret, so `raw_key` is required here. */
export interface CreatedApiKey extends ApiKey {
  raw_key: string;
}

export interface UserProfile {
  id: string;
  email: string;
  display_name?: string | null;
  role: "admin" | "member";
  /** A deactivated account keeps its history and memberships but cannot sign in. */
  disabled?: boolean;
  disabled_at?: string;
  created_at: string;
}

export interface Report {
  id: string;
  project_id: string;
  tool_name: string;
  tool_version?: string | null;
  scan_type: string;
  scan_target?: string | null;
  status: string;
  total_findings?: number | null;
  branch?: string | null;
  commit_sha?: string | null;
  base_revision?: string;
  scan_mode?: "full" | "incremental";
  changed_files?: string[];
  error_message?: string;
  created_at: string;
  completed_at?: string | null;
}

// The server stores an unfinished report as `processing`; openapi.yaml documents the
// same state as `pending`. Both mean "still running" (see `isReportInProgress`).
export type ReportStatus = "processing" | "pending" | "completed" | "failed";

export interface SeverityCount {
  severity: string;
  count: number;
  blocking_count: number;
}

export interface AnalysisStateCount {
  state: string;
  count: number;
}

export interface ProjectStats {
  total_findings: number;
  blocking_count: number;
  waiver_count: number;
  /** Waiver requests still waiting for a decision. They do not count in the gate. */
  pending_waiver_count?: number;
  report_count: number;
  by_severity: SeverityCount[];
  by_analysis_state?: AnalysisStateCount[];
  latest_report?: Report;
}

export interface IngestResponse {
  report_id: string;
  total_findings: number;
  threshold_breached: boolean;
  /** The mode actually used. */
  scan_mode: "full" | "incremental";
  /** Present when an incremental scan had to fall back to full. */
  fallback_reason?: "unsupported_scanner" | "missing_baseline";
  introduced_count: number;
  pre_existing_count: number;
  replayed: boolean;
}

export type AgingBucketName = "new" | "aging" | "stale" | "debt";

export interface AgingBucketCount {
  bucket: AgingBucketName;
  count: number;
  overdue: number;
}

/** An open finding past the date its severity says it should be fixed by. */
export interface OverdueFinding {
  id: string;
  title: string;
  severity: string;
  age_days: number;
  sla_days: number;
  due_date: string;
  reopened: boolean;
}

export interface WeeklyNew {
  /** The Monday the week starts on. */
  week: string;
  count: number;
}

/** How old a project's open findings are, which are overdue, and how many arrive each week. */
export interface Aging {
  buckets: AgingBucketCount[];
  overdue_total: number;
  overdue: OverdueFinding[];
  reopened: number;
  new_per_week: WeeklyNew[];
  /** The project has more open findings than the report covers; the oldest were counted. */
  truncated: boolean;
}

/** An environment a scan described: where the code runs, and how exposed it is. */
export interface Environment {
  id: string;
  project_id: string;
  name: string;
  tier: string;
  internet_facing: boolean;
  data_sensitivity: string;
  created_at: string;
}

/** A repository, image, or other subject a scan ran against. */
export interface Target {
  id: string;
  project_id: string;
  name: string;
  kind: string;
  locator?: string;
  created_at: string;
}

/** A build artifact seen by scans, such as a container image or an SBOM. */
export interface Artifact {
  id: string;
  project_id: string;
  target_id?: string;
  artifact_type: string;
  name: string;
  version?: string;
  digest?: string;
  locator?: string;
  created_at: string;
}

export type WatcherStatus = "disabled" | "server_off" | "waiting" | "ok" | "stale" | "failing";

/** A project's own watcher settings and what they amount to on this server. */
export interface ProjectWatcher {
  enabled: boolean;
  interval_seconds: number;
  default_interval_seconds: number;
  min_interval_seconds: number;
  max_interval_seconds: number;
  /** The server runs the watcher at all. A project can be on while the server has it off. */
  server_enabled: boolean;
  effective_enabled: boolean;
  effective_interval_seconds: number;
  last_poll_at?: string;
  status: WatcherStatus;
  /** False when the status is stale or failing. */
  healthy: boolean;
}

/** The watcher's health across the whole server. */
export interface WatcherHealth {
  last_successful_poll_at?: string;
  last_poll_attempt_at?: string;
  last_error?: string;
  consecutive_failures: number;
  healthy: boolean;
  stale: boolean;
  staleness_window?: string;
}

/** The whole server at a glance, for global admins. */
export interface AdminStatus {
  projects: number;
  users: number;
  open_findings: number;
  reports: number;
  oldest_settled_report_at?: string | null;
}

export interface RetentionPreview {
  older_than_days: number;
  cutoff: string;
  stale_reports: number;
}

export interface RetentionResult {
  older_than_days: number;
  cutoff: string;
  deleted_reports: number;
  deleted_report_ids?: string[];
  /** More reports are past the window than one run removes; run it again for the rest. */
  truncated?: boolean;
}
