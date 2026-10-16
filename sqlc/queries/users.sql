-- name: CreateUser :one
INSERT INTO users (email, display_name, password_hash, role)
VALUES (lower(sqlc.arg(email)::text), sqlc.narg(display_name), sqlc.narg(password_hash), 'member')
RETURNING *;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE lower(email) = lower(sqlc.arg(email)::text);

-- name: GetUserByID :one
SELECT * FROM users WHERE id = $1;

-- name: ClearUserPassword :exec
UPDATE users SET password_hash = NULL, updated_at = NOW() WHERE id = $1;

-- name: ListUsersByIDs :many
SELECT * FROM users WHERE id = ANY($1::uuid[]) ORDER BY email;

-- name: SetUserPassword :exec
UPDATE users SET password_hash = $2, token_version = token_version + 1, updated_at = NOW() WHERE id = $1;

-- name: SetUserRole :one
UPDATE users SET role = $2 WHERE id = $1
RETURNING *;

-- name: ChangeUserRole :one
-- Changes the global role and starts a new token generation, so the new role
-- applies to sessions that are already open instead of at their next refresh.
UPDATE users SET role = $2, token_version = token_version + 1, updated_at = NOW()
WHERE id = $1
RETURNING *;

-- name: SetUserDisabled :one
-- Deactivating also starts a new token generation, which ends open sessions at
-- their next request. Reactivating leaves the generation alone.
UPDATE users SET
    disabled_at = CASE WHEN sqlc.arg(disabled)::boolean THEN COALESCE(disabled_at, NOW()) ELSE NULL END,
    token_version = CASE WHEN sqlc.arg(disabled)::boolean THEN token_version + 1 ELSE token_version END,
    updated_at = NOW()
WHERE id = sqlc.arg(id)
RETURNING *;

-- name: LockActiveAdmins :many
-- Locks the active global admins for the rest of the transaction, so two
-- concurrent demotions cannot each see another admin and leave none.
SELECT id FROM users WHERE role = 'admin' AND disabled_at IS NULL FOR UPDATE;

-- name: AcquireSetupLock :exec
SELECT pg_advisory_xact_lock($1::bigint);

-- name: CountUsers :one
-- Counts real accounts. The system account that migration 21 seeds on every
-- install is not a person and does not count.
SELECT COUNT(*) FROM users WHERE email <> 'system@specht.local';

-- name: CountAdmins :one
-- Counts the active global admins. First-run setup stays open while this is
-- zero, whatever other accounts exist.
SELECT COUNT(*) FROM users
WHERE role = 'admin' AND disabled_at IS NULL AND email <> 'system@specht.local';

-- name: CreateFirstAdmin :one
-- Creates the first admin, with its email marked as proven because the setup
-- token vouches for the operator, and only while no active global admin exists (the
-- seeded system account does not count). Members who registered earlier do not
-- close it. No row comes back when an admin exists, so two racing setups cannot
-- both win; the caller serialises them with an advisory lock.
INSERT INTO users (email, display_name, password_hash, role, email_proven)
SELECT lower(sqlc.arg(email)::text), sqlc.narg(display_name), sqlc.arg(password_hash)::text, 'admin', TRUE
WHERE NOT EXISTS (
    SELECT 1 FROM users
    WHERE role = 'admin' AND disabled_at IS NULL AND email <> 'system@specht.local'
)
RETURNING *;

-- name: ListUsers :many
-- Account directory for admin surfaces (project members, team rosters).
-- The filter matches a case-insensitive substring of the email; an empty
-- filter lists every account. Ordered by email so pages are stable.
SELECT * FROM users
WHERE (sqlc.arg(email_filter)::text = '' OR email ILIKE ('%' || sqlc.arg(email_filter)::text || '%') ESCAPE E'\\')
ORDER BY email ASC, id ASC
LIMIT sqlc.arg(page_limit) OFFSET sqlc.arg(page_offset);

-- name: GetUserTokenVersion :one
SELECT token_version FROM users WHERE id = $1;

-- name: BumpUserTokenVersion :exec
UPDATE users SET token_version = token_version + 1, updated_at = NOW() WHERE id = $1;

-- name: UpdateUserDisplayName :one
UPDATE users SET display_name = $2, updated_at = NOW() WHERE id = $1
RETURNING *;

-- name: LockUserForLogin :one
-- Takes a share lock on the account for the rest of the transaction and returns
-- what a password login has to confirm before it hands out a session. An SSO
-- link, a password change and a deactivation all update this row, so each one
-- either committed before this read (the login sees the change and is refused)
-- or waits until the session is stored and then ends it with the rest.
SELECT password_hash, disabled_at, token_version FROM users WHERE id = $1 FOR SHARE;

-- name: LockUserForLink :one
-- Locks the account row for the rest of the transaction before an SSO link
-- changes it, and returns whether the account is deactivated. A deactivation
-- updates the same row, so the link sees its result instead of a read taken
-- earlier.
SELECT disabled_at FROM users WHERE id = $1 FOR NO KEY UPDATE;
