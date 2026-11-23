-- The "Needs you" page: what is waiting on one person across their projects. Every query takes
-- the project ids the caller can reach, so a project they cannot see never contributes a row.

-- name: ListManagedProjectIDs :many
-- Projects where a user holds manager rights or above directly or through a team, the roles that
-- may decide a waiver request. "editor" is the old name of manager, as in EffectiveProjectRole.
SELECT pm.project_id FROM project_members pm
WHERE pm.user_id = $1 AND pm.role IN ('admin', 'manager', 'editor')
UNION
SELECT pt.project_id FROM project_teams pt
JOIN team_members tm ON tm.team_id = pt.team_id
WHERE tm.user_id = $1 AND pt.role IN ('admin', 'manager', 'editor');

-- name: ListPendingWaiverRequests :many
-- Pending requests in the given projects, oldest first.
SELECT w.id, w.project_id, p.slug AS project_slug, p.name AS project_name, w.name, w.reason,
       w.requested_by, COALESCE(w.requested_at, w.created_at)::timestamptz AS asked_at
FROM waivers w
JOIN projects p ON p.id = w.project_id
WHERE w.status = 'pending' AND w.project_id = ANY(sqlc.arg(project_ids)::uuid[])
ORDER BY asked_at ASC, w.id
LIMIT sqlc.arg(max_rows);

-- name: ListDecidedWaiverRequests :many
-- Requests one person made that were approved or rejected since a time, newest first. A request
-- that lapsed unanswered is rejected with the decision reason "expired".
SELECT w.id, w.project_id, p.slug AS project_slug, p.name AS project_name, w.name, w.status,
       w.decision_note, w.decision_reason, w.decided_at::timestamptz AS decided_at
FROM waivers w
JOIN projects p ON p.id = w.project_id
WHERE w.requested_by = sqlc.arg(user_id)
  AND w.status IN ('approved', 'rejected')
  AND w.decided_at >= sqlc.arg(since)
  AND w.project_id = ANY(sqlc.arg(project_ids)::uuid[])
ORDER BY w.decided_at DESC, w.id
LIMIT sqlc.arg(max_rows);

-- name: ListWaiversEnding :many
-- Approved waivers that end between two times, soonest first.
SELECT w.id, w.project_id, p.slug AS project_slug, p.name AS project_name, w.name,
       w.expires_at::timestamptz AS ends_at
FROM waivers w
JOIN projects p ON p.id = w.project_id
WHERE w.status = 'approved' AND w.enabled
  AND w.expires_at > sqlc.arg(after) AND w.expires_at <= sqlc.arg(until)
  AND w.project_id = ANY(sqlc.arg(project_ids)::uuid[])
ORDER BY w.expires_at ASC, w.id
LIMIT sqlc.arg(max_rows);

-- name: ListOpenFindingsAssignedTo :many
-- Open findings assigned to one person, most severe first.
SELECT f.id, f.project_id, p.slug AS project_slug, p.name AS project_name, f.current_title,
       f.current_severity, f.last_seen_at::timestamptz AS last_seen_at
FROM findings f
JOIN projects p ON p.id = f.project_id
WHERE f.assignee_id = sqlc.arg(user_id)
  AND f.state IN ('open', 'reopened')
  AND f.project_id = ANY(sqlc.arg(project_ids)::uuid[])
ORDER BY f.current_severity_rank DESC, f.last_seen_at DESC, f.id
LIMIT sqlc.arg(max_rows);

-- name: CountOpenFindingsAssignedTo :one
SELECT COUNT(*) FROM findings f
WHERE f.assignee_id = sqlc.arg(user_id)
  AND f.state IN ('open', 'reopened')
  AND f.project_id = ANY(sqlc.arg(project_ids)::uuid[]);
