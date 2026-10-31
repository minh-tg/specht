-- name: GetProjectStats :many
-- Open findings by severity. Blocking is not counted here: whether a finding
-- blocks depends on the policy floor, source policy and waivers, which only the
-- gate evaluates, so the use case takes the blocking numbers from the gate.
SELECT
    f.current_severity AS severity,
    MIN(f.current_severity_rank)::smallint AS severity_rank,
    COUNT(*)::int AS count
FROM open_findings f
WHERE f.project_id = $1
GROUP BY f.current_severity
ORDER BY MIN(f.current_severity_rank);

-- name: GetProjectAnalysisStateCounts :many
SELECT
    COALESCE(NULLIF(f.analysis_state, ''), 'unanalyzed')::text AS state,
    COUNT(*)::int AS count
FROM open_findings f
WHERE f.project_id = $1
GROUP BY COALESCE(NULLIF(f.analysis_state, ''), 'unanalyzed')
ORDER BY state ASC;

-- name: GetProjectWaiverCount :one
SELECT COUNT(*)::int AS count
FROM waivers
WHERE project_id = $1 AND status = 'approved' AND enabled = true
  AND (expires_at IS NULL OR expires_at > NOW());

-- name: GetProjectPendingWaiverCount :one
SELECT COUNT(*)::int AS count
FROM waivers
WHERE project_id = $1 AND status = 'pending';

-- name: GetProjectReportCount :one
SELECT COUNT(*)::int AS count
FROM reports
WHERE project_id = $1;

-- name: GetProjectLatestReport :one
SELECT
    id, project_id, tool_name, tool_version, scan_type,
    scan_target, status, total_findings, branch, commit_sha,
    scan_completeness, created_at, completed_at,
    CAST((raw_data = 'null'::jsonb) IS TRUE AS boolean) AS raw_data_expired
FROM reports
WHERE project_id = $1
ORDER BY created_at DESC, id DESC
LIMIT 1;
-- name: GetProjectLatestCompletedReport :one
-- Completion order can differ from receipt order when ingests overlap.
SELECT
    id, project_id, tool_name, tool_version, scan_type,
    scan_target, status, total_findings, branch, commit_sha,
    scan_completeness, created_at, completed_at,
    CAST((raw_data = 'null'::jsonb) IS TRUE AS boolean) AS raw_data_expired
FROM reports
WHERE project_id = $1 AND status = 'completed'
ORDER BY COALESCE(completed_at, created_at) DESC, created_at DESC, id DESC
LIMIT 1;

-- name: GetAgingRows :many
-- Open findings, oldest first, for the aging report. The caller asks for one
-- row more than it will use, so that it can tell when the project has more than
-- the cap instead of silently dropping them.
SELECT
    f.id,
    f.current_title,
    f.current_severity,
    f.current_severity_rank,
    f.first_seen_at,
    f.state,
    EXISTS (
        SELECT 1 FROM finding_events e
        WHERE e.finding_id = f.id
          AND (e.event_type = 'regression'
               OR (e.event_type = 'state_changed' AND e.new_value = 'reopened'))
    ) AS reopened
FROM open_findings f
WHERE f.project_id = $1
ORDER BY f.first_seen_at ASC, f.id ASC
LIMIT $2;

-- name: GetNewFindingCounts :many
-- Findings first seen since a date, counted per week (weeks start on Monday,
-- UTC). Counts every finding introduced in the window, whatever it is today.
SELECT
    date_trunc('week', f.first_seen_at AT TIME ZONE 'UTC')::date AS week_start,
    COUNT(*)::int AS count
FROM findings f
WHERE f.project_id = $1
  AND f.first_seen_at >= $2
  AND f.state <> 'archived'
GROUP BY 1
ORDER BY 1;
