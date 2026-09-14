-- name: AdminOverview :one
-- Platform observability (SOLO-188): one row with global counts and the
-- oldest settled report, for the admin status surface.
SELECT
    (SELECT COUNT(*) FROM projects) AS project_count,
    (SELECT COUNT(*) FROM users) AS user_count,
    (SELECT COUNT(*) FROM findings WHERE state IN ('open', 'reopened')) AS open_finding_count,
    (SELECT COUNT(*) FROM reports) AS report_count,
    (SELECT MIN(COALESCE(completed_at, created_at)) FROM reports WHERE status IN ('completed', 'failed')) AS oldest_settled_report_at;
