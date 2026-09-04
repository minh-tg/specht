-- name: CreateAPIKey :one
INSERT INTO api_keys (project_id, name, key_prefix, key_hash, last_four, scopes, created_by)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: ListAPIKeysByProject :many
SELECT id, name, key_prefix, last_four, scopes, created_at, revoked_at
FROM api_keys
WHERE project_id = $1 AND revoked_at IS NULL
ORDER BY created_at DESC;

-- name: GetAPIKeyByHash :one
SELECT * FROM api_keys WHERE key_hash = $1;

-- name: RevokeAPIKey :one
UPDATE api_keys SET revoked_at = NOW() WHERE id = $1 AND project_id = $2
RETURNING *;
