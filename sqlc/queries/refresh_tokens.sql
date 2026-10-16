-- name: CreateRefreshToken :one
INSERT INTO refresh_tokens (user_id, token_hash, expires_at, family_id, family_started_at)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetRefreshTokenByHash :one
SELECT * FROM refresh_tokens WHERE token_hash = $1;

-- name: RevokeRefreshToken :one
UPDATE refresh_tokens SET revoked_at = NOW() WHERE id = $1 AND revoked_at IS NULL RETURNING *;

-- name: RevokeUserRefreshTokens :exec
UPDATE refresh_tokens SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL;

-- name: RevokeRefreshTokenFamily :exec
UPDATE refresh_tokens SET revoked_at = NOW() WHERE family_id = $1 AND revoked_at IS NULL;

-- name: PruneRefreshTokens :execrows
DELETE FROM refresh_tokens
WHERE id IN (
    SELECT r.id FROM refresh_tokens AS r
    WHERE r.expires_at < sqlc.arg(expired_before)::timestamptz
       OR (r.revoked_at IS NOT NULL AND r.revoked_at < sqlc.arg(revoked_before)::timestamptz)
    LIMIT sqlc.arg(batch_size)::int
);
