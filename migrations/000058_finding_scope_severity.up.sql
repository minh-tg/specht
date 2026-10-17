-- Severity is kept per scan scope. A scope is reports.scan_scope_hash (scanner,
-- target, artifact, branch and environment), the key auto-fix already uses.
-- findings.current_severity holds the highest severity across scopes, so a
-- scan from another branch or scanner can no longer lower a finding for the
-- whole project. Before this table, the last scan to ingest wrote the one
-- severity the finding carried.
--
-- The table is backfilled from finding_occurrences: one row per finding and
-- scope, taking the newest observation in that scope. findings.current_severity
-- is not rewritten here. A finding's project-wide severity is recomputed the
-- next time a scan reports it.
--
-- The finding_events check also gains severity_changed, which ingest writes
-- when a scope's severity differs from the value it last reported.
CREATE TABLE finding_scope_severities (
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    scope_hash TEXT NOT NULL,
    severity TEXT NOT NULL,
    severity_rank SMALLINT NOT NULL,
    report_id UUID REFERENCES reports(id) ON DELETE SET NULL,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (finding_id, scope_hash)
);

INSERT INTO finding_scope_severities (finding_id, scope_hash, severity, severity_rank, report_id, observed_at)
SELECT DISTINCT ON (o.finding_id, COALESCE(r.scan_scope_hash, ''))
    o.finding_id,
    COALESCE(r.scan_scope_hash, ''),
    o.severity,
    o.severity_rank,
    o.report_id,
    o.observed_at
FROM finding_occurrences o
JOIN reports r ON r.id = o.report_id
ORDER BY o.finding_id, COALESCE(r.scan_scope_hash, ''), o.observed_at DESC, o.id DESC;

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
        'report_deleted',
        'severity_changed'
    ));
