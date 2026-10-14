-- name: RevokePendingPasswordResets :exec
-- A new link for an account retires the ones issued before it.
UPDATE password_resets SET revoked_at = NOW()
WHERE user_id = $1 AND used_at IS NULL AND revoked_at IS NULL;

-- name: CreatePasswordReset :one
INSERT INTO password_resets (token_hash, user_id, created_by, expires_at)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: ClaimPasswordReset :one
-- Marks the link used. Of two requests with the same link only one gets a row
-- back; the other waits for the first to commit and then finds it used.
UPDATE password_resets SET used_at = NOW()
WHERE token_hash = $1
  AND used_at IS NULL AND revoked_at IS NULL AND expires_at > NOW()
RETURNING *;
