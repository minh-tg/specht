DROP INDEX IF EXISTS findings_introduced_by_report_id_idx;

ALTER TABLE findings
DROP COLUMN IF EXISTS introduced_by_report_id,
DROP COLUMN IF EXISTS introduced_commit_sha;

ALTER TABLE reports
DROP CONSTRAINT IF EXISTS reports_scan_mode_check;

ALTER TABLE reports
DROP COLUMN IF EXISTS base_revision,
DROP COLUMN IF EXISTS changed_files,
DROP COLUMN IF EXISTS scan_mode;
