-- name: UpsertSignoff :one
INSERT INTO signoffs (finding_id, status, reviewed_by, comment)
VALUES ($1, $2, $3, $4)
ON CONFLICT (finding_id) DO UPDATE SET
    status = EXCLUDED.status,
    reviewed_by = EXCLUDED.reviewed_by,
    comment = EXCLUDED.comment,
    updated_at = now()
RETURNING *;

-- name: GetSignoffByFinding :one
SELECT * FROM signoffs WHERE finding_id = $1;
