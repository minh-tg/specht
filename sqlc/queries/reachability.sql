-- name: UpsertReachability :one
INSERT INTO reachability_assessments (finding_id, state, evidence, assessed_by)
VALUES ($1, $2, $3, $4)
ON CONFLICT (finding_id, assessed_by) DO UPDATE SET
    state = EXCLUDED.state,
    evidence = EXCLUDED.evidence,
    updated_at = NOW()
RETURNING *;

-- name: ListReachabilityByFinding :many
SELECT * FROM reachability_assessments
WHERE finding_id = $1
ORDER BY updated_at DESC;

-- name: GetReachability :one
SELECT * FROM reachability_assessments WHERE id = $1;

-- name: LatestReachabilityByFinding :one
-- The most recent assessment for one finding, if any. Ordered by updated_at
-- so the "latest" reflects the most recent write (upserts update state
-- without touching created_at). Returns pgx.ErrNoRows when no assessment
-- exists yet.
SELECT * FROM reachability_assessments
WHERE finding_id = $1
ORDER BY updated_at DESC
LIMIT 1;

-- name: LatestReachabilityByFindings :many
-- The latest assessment per finding for a set of finding ids (one row per
-- finding that has any assessment). Used to batch-load gate blocker
-- reachability without an N+1 query.
SELECT DISTINCT ON (finding_id) *
FROM reachability_assessments
WHERE finding_id = ANY($1::uuid[])
ORDER BY finding_id, updated_at DESC;
