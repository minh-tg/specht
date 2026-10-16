-- name: LockKeyCreator :one
-- Takes a share lock on an active account for the rest of the transaction. A
-- deactivation updates the same row, and that update conflicts with the lock,
-- so a key insert and a deactivation run one after the other: the key is
-- either refused (the account is already deactivated) or in place before the
-- deactivation revokes the account's keys. A foreign key check alone does not
-- conflict with that update, so it cannot do this. No row means the account is
-- deactivated or does not exist.
SELECT id FROM users WHERE id = $1 AND disabled_at IS NULL FOR SHARE;

-- name: CreateAPIKey :one
INSERT INTO api_keys (project_id, name, key_prefix, key_hash, last_four, scopes, created_by, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING *;

-- name: TouchAPIKeyLastUsed :exec
UPDATE api_keys SET last_used_at = NOW() WHERE id = $1 AND revoked_at IS NULL;

-- name: ListAPIKeysByProject :many
-- creator_is_member is false once the account that created the key no longer
-- holds a direct project_members row or a seat in a linked team. The key is
-- still live: a CI key may outlive the person on purpose.
SELECT
    ak.id,
    ak.name,
    ak.key_prefix,
    ak.last_four,
    ak.scopes,
    ak.created_at,
    ak.revoked_at,
    (
        EXISTS (
            SELECT 1 FROM project_members pm
            WHERE pm.project_id = ak.project_id AND pm.user_id = ak.created_by
        ) OR EXISTS (
            SELECT 1 FROM project_teams pt
            JOIN team_members tm ON tm.team_id = pt.team_id
            WHERE pt.project_id = ak.project_id AND tm.user_id = ak.created_by
        )
    )::boolean AS creator_is_member
FROM api_keys ak
WHERE ak.project_id = $1 AND ak.revoked_at IS NULL
ORDER BY ak.created_at DESC;

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
        (SELECT u.id
         FROM users u
         WHERE u.email = 'system@specht.local'
         LIMIT 1)
    ) AS created_by
FROM api_keys ak
WHERE ak.key_hash = $1
  -- A key does not outlive the account that created it. Revocation at
  -- deactivation covers the normal path; this keeps a key that slipped past it,
  -- or that predates it, from authenticating while its creator is deactivated.
  AND NOT EXISTS (
      SELECT 1
      FROM users cu
      WHERE cu.id = ak.created_by
        AND cu.disabled_at IS NOT NULL
  );

-- name: RevokeAPIKey :one
UPDATE api_keys SET revoked_at = NOW() WHERE id = $1 AND project_id = $2
RETURNING *;

-- name: RevokeAPIKeysByCreator :many
WITH revoked AS (
    UPDATE api_keys SET revoked_at = NOW()
    WHERE created_by = $1 AND revoked_at IS NULL
    RETURNING id, project_id, name
)
SELECT r.id, p.slug AS project_slug, r.name
FROM revoked r
JOIN projects p ON p.id = r.project_id
ORDER BY p.slug, r.name, r.id;
