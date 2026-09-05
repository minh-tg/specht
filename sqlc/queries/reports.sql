-- name: CreateReport :one
INSERT INTO reports (
    project_id, tool_name, tool_version, scan_type,
    target_id, artifact_id, environment_id,
    scan_target, scan_scope, scan_scope_hash,
    scan_completeness, scanner_config_hash,
    branch, commit_sha, status,
    total_findings, parser_version,
    started_at, error_message, raw_report_hash,
    raw_data
) VALUES (
    $1, $2, $3, $4,
    $5, $6, $7,
    $8, $9, $10,
    $11, $12,
    $13, $14, $15,
    $16, $17,
    $18, $19, $20,
    $21
) RETURNING *;

-- name: GetReportByID :one
SELECT * FROM reports WHERE id = $1;

-- name: ListReportsByProject :many
SELECT * FROM reports
WHERE project_id = $1
ORDER BY created_at DESC
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
WHERE project_id = $1 AND tool_name = $2 AND status = 'completed'
ORDER BY created_at DESC
LIMIT 1;
