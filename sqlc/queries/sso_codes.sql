-- name: CreateSSOCode :exec
INSERT INTO sso_exchange_codes (code_hash, user_id, email, role, expires_at)
VALUES ($1, $2, $3, $4, $5);

-- name: ConsumeSSOCode :one
DELETE FROM sso_exchange_codes
WHERE code_hash = $1 AND expires_at > $2
RETURNING code_hash, user_id, email, role, expires_at;

-- name: PruneSSOCodes :exec
DELETE FROM sso_exchange_codes
WHERE ctid IN (
    SELECT ctid FROM sso_exchange_codes
    WHERE expires_at <= NOW()
    LIMIT 1000
);
