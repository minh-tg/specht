-- Restores the bytes-only dedup index. This FAILS if the reports table now
-- holds more than one completed report with the same project_id and
-- raw_report_hash but different commit_sha values: those rows violate the
-- old index and must be resolved before the down migration can run.
DROP INDEX IF EXISTS idx_reports_dedup;

CREATE UNIQUE INDEX idx_reports_dedup
    ON reports(project_id, raw_report_hash)
    WHERE raw_report_hash IS NOT NULL AND status = 'completed';
