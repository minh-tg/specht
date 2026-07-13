-- name: UpsertReachability :one
INSERT INTO reachability_assessments (finding_id, reachable, evidence, assessed_by)
VALUES ($1, $2, $3, $4)
ON CONFLICT (finding_id, assessed_by) DO UPDATE SET
    reachable = EXCLUDED.reachable,
    evidence = EXCLUDED.evidence
RETURNING *;

-- name: ListReachabilityByFinding :many
SELECT * FROM reachability_assessments
WHERE finding_id = $1
ORDER BY created_at DESC;

-- name: GetReachability :one
SELECT * FROM reachability_assessments WHERE id = $1;
