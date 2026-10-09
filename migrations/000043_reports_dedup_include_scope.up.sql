-- The dedup key gains the scan-scope hash. A branch and its fast-forward
-- merge can carry the same commit and byte-identical scanner output, but
-- they are different scans: the merge needs its own report so branch-scoped
-- auto-fix runs against it. A NULL scan_scope_hash compares as the empty
-- string, matching the commit column's treatment.
DROP INDEX IF EXISTS idx_reports_dedup;

CREATE UNIQUE INDEX idx_reports_dedup
    ON reports(project_id, raw_report_hash, COALESCE(commit_sha, ''), COALESCE(scan_scope_hash, ''))
    WHERE raw_report_hash IS NOT NULL AND status = 'completed';
