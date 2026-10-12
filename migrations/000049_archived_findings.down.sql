DELETE FROM finding_events WHERE event_type = 'report_deleted';
UPDATE findings SET state = 'fixed' WHERE state = 'archived';

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
        'regression'
    ));

ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_state_check;
ALTER TABLE findings
    ADD CONSTRAINT findings_state_check CHECK (state IN ('open', 'fixed', 'reopened'));
