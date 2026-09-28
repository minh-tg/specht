-- name: CreateUser :one
INSERT INTO users (email, display_name, password_hash, role)
VALUES ($1, $2, $3, 'member')
RETURNING *;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = $1;

-- name: GetUserByID :one
SELECT * FROM users WHERE id = $1;

-- name: SetUserRole :one
UPDATE users SET role = $2 WHERE id = $1
RETURNING *;

-- name: ListUsers :many
-- Account directory for admin surfaces (project members, team rosters).
-- The filter matches a case-insensitive substring of the email; an empty
-- filter lists every account. Ordered by email so pages are stable.
SELECT * FROM users
WHERE (sqlc.arg(email_filter)::text = '' OR email ILIKE ('%' || sqlc.arg(email_filter)::text || '%') ESCAPE E'\\')
ORDER BY email ASC, id ASC
LIMIT sqlc.arg(page_limit) OFFSET sqlc.arg(page_offset);

-- name: UpdateUserDisplayName :one
UPDATE users SET display_name = $2, updated_at = NOW() WHERE id = $1
RETURNING *;
