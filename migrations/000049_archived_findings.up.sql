-- Deleting a report can leave a finding with no evidence at all. Such a
-- finding becomes archived: it stays readable with its history, but it no
-- longer blocks, counts as open or ages. Fixed means a scan stopped reporting
-- the finding; archived means the report that showed it is gone.
ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_state_check;
ALTER TABLE findings
    ADD CONSTRAINT findings_state_check CHECK (state IN ('open', 'fixed', 'reopened', 'archived'));

ALTER TABLE finding_events DROP CONSTRAINT IF EXISTS finding_events_event_type_check;
ALTER TABLE finding_events
    ADD CONSTRAINT finding_events_event_type_check
    CHECK (event_type IN (
        'state_changed', 'triage_changed', 'assigned', 'commented',
        'analysis_changed', 'waiver_expired',
        'reopened_severity_change', 'reopened_fix_available',
        'bulk_triage_applied',
        'auto_rule_applied', 'auto_rule_skipped',
        'approval_requested', 'approval_granted', 'approval_denied',
        'verified_fixed',
        'regression',
        'report_deleted'
    ));
