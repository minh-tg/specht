-- rescan-verification writes a verified_fixed event when a
-- newer complete report from the same scanner no longer carries a finding.
-- Add it to the allowed event-type enum so CreateEvent does not violate the
-- finding_events_event_type_check constraint.
ALTER TABLE finding_events
DROP CONSTRAINT IF EXISTS finding_events_event_type_check;

ALTER TABLE finding_events
ADD CONSTRAINT finding_events_event_type_check
  CHECK (event_type IN (
    'state_changed', 'triage_changed', 'assigned', 'commented',
    'analysis_changed', 'waiver_expired',
    'reopened_severity_change', 'reopened_fix_available',
    'bulk_triage_applied',
    'auto_rule_applied', 'auto_rule_skipped',
    'approval_requested', 'approval_granted', 'approval_denied',
    'verified_fixed'
  ));
