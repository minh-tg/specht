-- name: GetUserIdentity :one
SELECT * FROM user_identities
WHERE issuer = $1 AND subject = $2;

-- name: GetUserIdentityForUser :one
SELECT * FROM user_identities
WHERE user_id = $1 AND issuer = $2;

-- name: CreateUserIdentity :one
-- Links the identity and, in the same statement, marks the account's email as
-- proven when the provider vouched for it. A refused link (unique violation)
-- rolls the mark back with it.
WITH proven AS (
    UPDATE users SET email_proven = TRUE, updated_at = NOW()
    WHERE id = sqlc.arg(user_id) AND sqlc.arg(email_verified)::boolean
)
INSERT INTO user_identities (user_id, issuer, subject)
VALUES (sqlc.arg(user_id), sqlc.arg(issuer), sqlc.arg(subject))
RETURNING *;
