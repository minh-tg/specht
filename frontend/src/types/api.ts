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
}

export interface Finding {
  id: string;
  project_id: string;
  finding_kind: string;
  fingerprint: string;
  current_title: string;
  current_severity: Severity;
  current_score: number | null;
  state: TechnicalState;
  triage_status: string;
  analysis_state: AnalysisState;
  gate_effect: GateEffect;
  first_seen_at: string;
  last_seen_at: string;
  created_at: string;
  updated_at: string;
  /** Deployment context of the finding's latest observation. Absent when
   * the finding has no linked scan occurrence. */
  context?: FindingContext;
  /** Source-aware fix guidance from the latest observation. */
  remediation?: FindingRemediation;
  /** Exact package, rule, resource, file, or URL when supplied. */
  location?: FindingLocation;
  /** Reviewable remediation proposal built from dimensions + guidance. */
  suggestion?: FindingSuggestion;
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
  confidence: string;
  source?: string;
}

export interface GateStatus {
  threshold_breached: boolean;
  blocking_count: number;
  blocked_by?: string[];
  blocked_by_reachability?: Record<string, ReachabilityState>;
  waived_count?: number;
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

export interface LoginResponse {
  token: string;
  refresh_token: string;
  user_id: string;
  email: string;
}

export interface ApiKey {
  id: string;
  name: string;
  key_prefix: string;
  project_id: string;
  created_at: string;
}

export interface Report {
  id: string;
  project_id: string;
  tool_name: string;
  tool_version: string | null;
  scan_type: string;
  scan_target: string | null;
  status: string;
  total_findings: number | null;
  branch: string | null;
  commit_sha: string | null;
  created_at: string;
  completed_at: string | null;
}
