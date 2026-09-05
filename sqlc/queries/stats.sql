-- name: GetProjectStats :many
SELECT
    f.current_severity AS severity,
    COUNT(*)::int AS count,
    COUNT(*) FILTER (WHERE f.gate_effect = 'block')::int AS blocking_count
FROM findings f
WHERE f.project_id = $1
GROUP BY f.current_severity
ORDER BY MIN(f.current_severity_rank);

-- name: GetProjectWaiverCount :one
SELECT COUNT(*)::int AS count
FROM waivers
WHERE project_id = $1 AND enabled = true;

-- name: GetProjectReportCount :one
SELECT COUNT(*)::int AS count
FROM reports
WHERE project_id = $1;

-- name: GetProjectLatestReport :one
SELECT
    id, project_id, tool_name, tool_version, scan_type,
    scan_target, status, total_findings, branch, commit_sha,
    created_at, completed_at
FROM reports
WHERE project_id = $1
ORDER BY created_at DESC
LIMIT 1;
-- name: GetAgingRows :many
SELECT
    f.id,
    f.current_title,
    f.current_severity,
    f.current_severity_rank,
    f.first_seen_at,
    f.state,
    EXISTS (
        SELECT 1 FROM finding_events e
        WHERE e.finding_id = f.id AND e.event_type LIKE 'reopened%'
    ) AS reopened
FROM findings f
WHERE f.project_id = $1
ORDER BY f.first_seen_at ASC
LIMIT 10000;
