-- name: GetUserIdentity :one
SELECT * FROM user_identities
WHERE issuer = $1 AND subject = $2;

-- name: GetUserIdentityForUser :one
SELECT * FROM user_identities
WHERE user_id = $1 AND issuer = $2;

-- name: CreateUserIdentity :one
INSERT INTO user_identities (user_id, issuer, subject)
VALUES ($1, $2, $3)
RETURNING *;
