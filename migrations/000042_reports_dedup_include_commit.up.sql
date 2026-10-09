-- The dedup key gains the commit a scan belongs to. Scanner output is often
-- byte-identical across commits when nothing changed, so hashing raw bytes
-- alone rejected a legitimate report from a different commit. A NULL
-- commit_sha compares as the empty string, so two ingests that both omit a
-- commit still dedupe against each other.
DROP INDEX IF EXISTS idx_reports_dedup;

CREATE UNIQUE INDEX idx_reports_dedup
    ON reports(project_id, raw_report_hash, COALESCE(commit_sha, ''))
    WHERE raw_report_hash IS NOT NULL AND status = 'completed';
