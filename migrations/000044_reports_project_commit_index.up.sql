-- The PR check asks whether any scan completed for an exact commit, and the
-- incremental baseline lookup resolves a base revision to a report. Both
-- filter reports on (project_id, commit_sha); only the project and the
-- created_at ordering were indexed, so each lookup walked every report of
-- the project. Reports without a commit never match an equality, so they stay
-- out of the index.
CREATE INDEX IF NOT EXISTS idx_reports_project_commit
ON reports (project_id, commit_sha)
WHERE commit_sha IS NOT NULL;
