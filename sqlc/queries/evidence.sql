-- name: CreateEvidence :one
INSERT INTO evidence_artifacts (finding_id, type, url, description, uploaded_by)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: ListEvidenceByFinding :many
SELECT * FROM evidence_artifacts
WHERE finding_id = $1
ORDER BY created_at DESC, id DESC;

-- name: GetEvidenceByID :one
SELECT * FROM evidence_artifacts WHERE id = $1;

-- name: DeleteEvidence :exec
DELETE FROM evidence_artifacts WHERE id = $1;
