ALTER TABLE findings ADD COLUMN IF NOT EXISTS analysis_state TEXT NOT NULL DEFAULT 'unanalyzed'
  CHECK (analysis_state IN (
    'unanalyzed', 'in_triage', 'exploitable',
    'false_positive', 'not_affected', 'accepted_risk', 'wont_fix'
  ));

ALTER TABLE findings ADD COLUMN IF NOT EXISTS gate_effect TEXT NOT NULL DEFAULT 'block'
  CHECK (gate_effect IN ('block', 'ignore'));

ALTER TABLE findings ADD COLUMN IF NOT EXISTS analysis_expires_at TIMESTAMPTZ;

ALTER TABLE findings ADD COLUMN IF NOT EXISTS analysis_reason TEXT;

ALTER TABLE findings ADD COLUMN IF NOT EXISTS analysis_source TEXT NOT NULL DEFAULT 'system'
  CHECK (analysis_source IN ('system', 'manual', 'bulk', 'auto_rule'));

ALTER TABLE findings ADD COLUMN IF NOT EXISTS analysis_updated_at TIMESTAMPTZ;

ALTER TABLE findings ADD COLUMN IF NOT EXISTS analysis_updated_by UUID REFERENCES users(id);

ALTER TABLE findings ADD COLUMN IF NOT EXISTS manual_override BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE findings ADD COLUMN IF NOT EXISTS review_required BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE findings ADD COLUMN IF NOT EXISTS approval_status TEXT NOT NULL DEFAULT 'none'
  CHECK (approval_status IN ('none', 'required', 'approved', 'rejected'));

ALTER TABLE findings ADD COLUMN IF NOT EXISTS approved_by UUID REFERENCES users(id);

ALTER TABLE findings ADD COLUMN IF NOT EXISTS approved_at TIMESTAMPTZ;

ALTER TABLE findings ADD COLUMN IF NOT EXISTS fingerprint_version INT NOT NULL DEFAULT 1;

CREATE INDEX IF NOT EXISTS idx_findings_gate_eval
  ON findings(project_id, state, current_severity_rank)
  WHERE state IN ('open', 'reopened');

CREATE INDEX IF NOT EXISTS idx_findings_expiry
  ON findings(analysis_expires_at)
  WHERE gate_effect = 'ignore' AND analysis_expires_at IS NOT NULL;

ALTER TABLE finding_events DROP CONSTRAINT IF EXISTS finding_events_event_type_check;

ALTER TABLE finding_events ADD CONSTRAINT finding_events_event_type_check
  CHECK (event_type IN (
    'state_changed', 'triage_changed', 'assigned', 'commented',
    'analysis_changed', 'waiver_expired',
    'reopened_severity_change', 'reopened_fix_available',
    'bulk_triage_applied',
    'auto_rule_applied', 'auto_rule_skipped',
    'approval_requested', 'approval_granted', 'approval_denied'
  ));
