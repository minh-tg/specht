-- Revision attribution for introduced-by-change (SOLO-184) and incremental
-- analysis (SOLO-165). Reports carry the revision they scanned plus the base
-- they were compared against; findings materialize their introducing report
-- so gates, CLI, MCP, and PR views can target introduced risk without
-- ignoring existing debt. Findings with no linked scan (e.g. watcher rows)
-- keep NULL attribution: unattributed is explicit, never a guess.
ALTER TABLE reports
ADD COLUMN base_revision TEXT,
ADD COLUMN changed_files JSONB NOT NULL DEFAULT '[]'::jsonb,
ADD COLUMN scan_mode TEXT NOT NULL DEFAULT 'full';

ALTER TABLE reports
ADD CONSTRAINT reports_scan_mode_check
  CHECK (scan_mode IN ('full', 'incremental'));

ALTER TABLE findings
ADD COLUMN introduced_by_report_id UUID REFERENCES reports(id) ON DELETE SET NULL,
ADD COLUMN introduced_commit_sha TEXT;

-- Backfill: attribute each finding to its earliest observed scan. Findings
-- never observed in a report stay NULL (explicitly unattributed).
UPDATE findings f
SET introduced_by_report_id = eo.report_id,
    introduced_commit_sha = r.commit_sha
FROM (
    SELECT DISTINCT ON (fo.finding_id) fo.finding_id, fo.report_id
    FROM finding_occurrences fo
    WHERE fo.report_id IS NOT NULL
    ORDER BY fo.finding_id, fo.observed_at ASC
) eo
JOIN reports r ON r.id = eo.report_id
WHERE f.id = eo.finding_id
  AND f.introduced_by_report_id IS NULL;

CREATE INDEX IF NOT EXISTS findings_introduced_by_report_id_idx
ON findings (introduced_by_report_id);
