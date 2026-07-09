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
SELECT *
FROM reports
WHERE project_id = $1
ORDER BY created_at DESC
LIMIT 1;
