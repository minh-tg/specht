-- Rolling back drops finding_scope_severities. The severity_changed events
-- written by the release are copied to migration_000058_severity_changed_events
-- before they are deleted, because the restored check rejects that event type.
-- Keep the backup until the rollback window closes, then drop it in a separate
-- reviewed cleanup migration.
--
-- findings.current_severity is left as it is. The up migration did not rewrite
-- it, and the rolled-back code writes the severity of the last scan again.
-- The backup table may already exist when the chain is rolled back more than
-- once in the same database, so it is created only when missing and rows are
-- appended to it.
CREATE TABLE IF NOT EXISTS migration_000058_severity_changed_events (LIKE finding_events);

INSERT INTO migration_000058_severity_changed_events
SELECT * FROM finding_events WHERE event_type = 'severity_changed';

DELETE FROM finding_events WHERE event_type = 'severity_changed';

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

DROP TABLE finding_scope_severities;
