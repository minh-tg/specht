-- The older checks below allow neither the report_deleted event nor the
-- archived state, so both have to go before they are restored. They are
-- copied out first, because this file used to discard them for good:
--   migration_000049_report_deleted_events  the deleted event rows
--   migration_000049_archived_findings      ids of findings rewritten to fixed
-- Re-applying the up migration does not read them back. After it, restore by
-- hand:
--   INSERT INTO finding_events SELECT * FROM migration_000049_report_deleted_events
--       ON CONFLICT (id) DO NOTHING;
--   UPDATE findings SET state = 'archived'
--       WHERE id IN (SELECT finding_id FROM migration_000049_archived_findings)
--       AND state = 'fixed';
-- then drop both tables.
CREATE TABLE IF NOT EXISTS migration_000049_report_deleted_events (LIKE finding_events);
INSERT INTO migration_000049_report_deleted_events
SELECT * FROM finding_events WHERE event_type = 'report_deleted';

CREATE TABLE IF NOT EXISTS migration_000049_archived_findings (
    finding_id UUID PRIMARY KEY,
    saved_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
INSERT INTO migration_000049_archived_findings (finding_id)
SELECT id FROM findings WHERE state = 'archived'
ON CONFLICT (finding_id) DO NOTHING;

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
