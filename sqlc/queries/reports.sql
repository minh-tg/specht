-- name: CreateReport :one
INSERT INTO reports (
    project_id, tool_name, tool_version, scan_type,
    target_id, artifact_id, environment_id,
    scan_target, scan_scope, scan_scope_hash,
    scan_completeness, scanner_config_hash,
    branch, commit_sha, status,
    total_findings, parser_version,
    started_at, error_message, raw_report_hash,
    raw_data,
    base_revision, changed_files, scan_mode
) VALUES (
    $1, $2, $3, $4,
    $5, $6, $7,
    $8, $9, $10,
    $11, $12,
    $13, $14, $15,
    $16, $17,
    $18, $19, $20,
    $21,
    $22, $23, $24
) RETURNING *;

-- name: GetReportByID :one
SELECT * FROM reports WHERE id = $1;

-- name: ListReportsByProject :many
SELECT * FROM reports
WHERE project_id = $1
ORDER BY created_at DESC, id DESC
LIMIT $2 OFFSET $3;

-- name: UpdateReportStatus :one
UPDATE reports SET
    status = $2,
    total_findings = $3,
    completed_at = CASE WHEN $2 = 'completed' OR $2 = 'failed' THEN NOW() ELSE completed_at END,
    error_message = $4
WHERE id = $1 AND project_id = $5
RETURNING *;
-- name: LatestCompletedReportByScanner :one
SELECT id, tool_name, branch, commit_sha, scan_completeness, created_at
FROM reports
WHERE project_id = $1 AND tool_name = $2 AND status = 'completed' AND scan_mode = 'full'
ORDER BY created_at DESC, id DESC
LIMIT 1;

-- name: GetCompletedReportByCommit :one
-- Baseline resolution for incremental analysis: the newest
-- completed same-scanner report for an exact revision. pgx.ErrNoRows means
-- no baseline exists for the base revision — the caller falls back to a
-- full scan instead of guessing.
SELECT id, tool_name, branch, commit_sha, base_revision, scan_mode, scan_completeness, created_at
FROM reports
WHERE project_id = $1 AND tool_name = $2 AND commit_sha = $3 AND status = 'completed' AND scan_mode = 'full'
ORDER BY created_at DESC, id DESC
LIMIT 1;

-- name: HasCompletedReportForCommit :one
-- Whether any scanner completed a scan of an exact revision. A PR check
-- needs this to tell a commit with no scan evidence from a scan that found
-- nothing new.
SELECT EXISTS (
    SELECT 1 FROM reports
    WHERE project_id = $1 AND commit_sha = $2 AND status = 'completed'
);

-- name: GetLatestCompletedFullReportByBranch :one
-- Baseline resolution when base_revision names a branch rather than a
-- commit: the newest completed full scan from the same scanner on that
-- branch. pgx.ErrNoRows means the branch has no full baseline yet.
SELECT id, tool_name, branch, commit_sha, base_revision, scan_mode, scan_completeness, created_at
FROM reports
WHERE project_id = $1 AND tool_name = $2 AND branch = $3 AND status = 'completed' AND scan_mode = 'full'
ORDER BY created_at DESC, id DESC
LIMIT 1;

-- name: CountStaleReports :one
-- Retention preview: settled (completed/failed) reports older
-- than the cutoff. Processing reports are never counted — an in-flight
-- scan must not look purgable.
SELECT COUNT(*) FROM reports
WHERE status IN ('completed', 'failed')
  AND COALESCE(completed_at, created_at) < $1;

-- name: DeleteStaleReports :many
-- Retention purge: deletes settled reports older than the
-- cutoff, returning their ids. Occurrences, watcher rows, and package
-- inventory cascade; finding attribution nulls (SET NULL); findings
-- themselves survive. Returns zero rows when nothing qualifies.
DELETE FROM reports
WHERE status IN ('completed', 'failed')
  AND COALESCE(completed_at, created_at) < $1
RETURNING id;

-- name: FindCompletedByHash :one
-- Duplicate-content guard: a completed report with the same raw-content
-- hash. pgx.ErrNoRows means this content is new (or only ever failed) —
-- the caller ingests normally.
SELECT id FROM reports
WHERE project_id = $1 AND raw_report_hash = $2 AND status = 'completed'
LIMIT 1;

-- name: DeleteReport :exec
-- Removes one report row (duplicate-cleanup path). Occurrences, watcher
-- rows, and inventory cascade; finding attribution nulls; findings
-- themselves survive.
DELETE FROM reports WHERE id = $1 AND project_id = $2;
