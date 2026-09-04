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
  current_severity: string;
  current_score: number | null;
  state: string;
  triage_status: string;
  analysis_state: string;
  gate_effect: string;
  first_seen_at: string;
  last_seen_at: string;
  created_at: string;
  updated_at: string;
}

export interface GateStatus {
  threshold_breached: boolean;
  blocking_count: number;
  blocked_by?: string[];
  blocked_by_reachability?: Record<string, string>;
  waived_count?: number;
}

export interface ReachabilityAssessment {
  id: string;
  finding_id: string;
  state: string;
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
  analysis_state: string;
  gate_effect: string;
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
