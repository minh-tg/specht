DROP INDEX IF EXISTS idx_findings_expiry;
DROP INDEX IF EXISTS idx_findings_gate_eval;

ALTER TABLE findings DROP COLUMN IF EXISTS fingerprint_version;
ALTER TABLE findings DROP COLUMN IF EXISTS approved_at;
ALTER TABLE findings DROP COLUMN IF EXISTS approved_by;
ALTER TABLE findings DROP COLUMN IF EXISTS approval_status;
ALTER TABLE findings DROP COLUMN IF EXISTS review_required;
ALTER TABLE findings DROP COLUMN IF EXISTS manual_override;
ALTER TABLE findings DROP COLUMN IF EXISTS analysis_updated_by;
ALTER TABLE findings DROP COLUMN IF EXISTS analysis_updated_at;
ALTER TABLE findings DROP COLUMN IF EXISTS analysis_source;
ALTER TABLE findings DROP COLUMN IF EXISTS analysis_reason;
ALTER TABLE findings DROP COLUMN IF EXISTS analysis_expires_at;
ALTER TABLE findings DROP COLUMN IF EXISTS gate_effect;
ALTER TABLE findings DROP COLUMN IF EXISTS analysis_state;

ALTER TABLE finding_events DROP CONSTRAINT IF EXISTS finding_events_event_type_check;

ALTER TABLE finding_events ADD CONSTRAINT finding_events_event_type_check
  CHECK (event_type IN
    ('state_changed', 'triage_changed', 'assigned', 'commented'));
