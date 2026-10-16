-- name: RevokePendingPasswordResets :exec
-- A new link for an account retires the ones issued before it.
UPDATE password_resets SET revoked_at = NOW()
WHERE user_id = $1 AND used_at IS NULL AND revoked_at IS NULL;

-- name: CreatePasswordReset :one
INSERT INTO password_resets (token_hash, user_id, created_by, expires_at)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: GetPasswordResetUserID :one
-- Names the account a link belongs to without spending the link, so the
-- redeem can lock that account before it touches the link.
SELECT user_id FROM password_resets WHERE token_hash = $1;

-- name: LockResettableUser :one
-- Locks an account that can take a password through a link: active and with a
-- local password. An account that signs in through an identity provider has no
-- password hash and a reset must not give it one. A concurrent deactivation,
-- password change or SSO link holds the same row lock, so this waits for it and
-- then re-reads the row; an account it turned ineligible returns no row.
SELECT id FROM users
WHERE id = $1 AND disabled_at IS NULL AND password_hash IS NOT NULL
FOR NO KEY UPDATE;

-- name: ClaimPasswordReset :one
-- Marks the link used. Of two requests with the same link only one gets a row
-- back; the other waits for the first to commit and then finds it used. A link
-- of a deactivated or password-less account is refused here as well, so the
-- rule does not depend on the caller having locked the account first.
UPDATE password_resets SET used_at = NOW()
WHERE token_hash = $1
  AND used_at IS NULL AND revoked_at IS NULL AND expires_at > NOW()
  AND EXISTS (
      SELECT 1 FROM users u
      WHERE u.id = password_resets.user_id
        AND u.disabled_at IS NULL AND u.password_hash IS NOT NULL
  )
RETURNING *;
