-- name: RevokeAccessToken :exec
INSERT INTO revoked_access_tokens (jti, expires_at)
VALUES ($1, $2)
ON CONFLICT (jti) DO UPDATE SET expires_at = EXCLUDED.expires_at;

-- name: PruneRevokedAccessTokens :exec
DELETE FROM revoked_access_tokens
WHERE ctid IN (
    SELECT ctid FROM revoked_access_tokens
    WHERE expires_at <= NOW()
    LIMIT 1000
);

-- name: IsAccessTokenRevoked :one
SELECT EXISTS (
    SELECT 1 FROM revoked_access_tokens
    WHERE jti = $1 AND expires_at > NOW()
) AS revoked;
