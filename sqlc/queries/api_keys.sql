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
SELECT
    ak.id,
    ak.project_id,
    ak.name,
    ak.key_prefix,
    ak.key_hash,
    ak.last_four,
    ak.scopes,
    ak.expires_at,
    ak.last_used_at,
    ak.created_at,
    ak.revoked_at,
    COALESCE(
        ak.created_by,
        (SELECT pm.user_id
         FROM project_members pm
         WHERE pm.project_id = ak.project_id
           AND pm.role = 'admin'
         ORDER BY pm.created_at, pm.user_id
         LIMIT 1),
        (SELECT pm.user_id
         FROM project_members pm
         WHERE pm.project_id = ak.project_id
         ORDER BY pm.created_at, pm.user_id
         LIMIT 1),
        (SELECT u.id
         FROM users u
         WHERE u.email = 'system@specht.local'
         LIMIT 1),
        (SELECT u.id
         FROM users u
         ORDER BY u.created_at, u.id
         LIMIT 1)
    ) AS created_by
FROM api_keys ak
WHERE ak.key_hash = $1;

-- name: RevokeAPIKey :one
UPDATE api_keys SET revoked_at = NOW() WHERE id = $1 AND project_id = $2
RETURNING *;
