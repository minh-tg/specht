-- name: CreateInvite :one
INSERT INTO invites (token_hash, project_id, role, email, created_by, expires_at)
VALUES ($1, $2, $3, sqlc.narg(email), $4, $5)
RETURNING *;

-- name: CountPendingInvites :one
SELECT COUNT(*) FROM invites
WHERE project_id = $1
  AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > NOW();

-- name: ListPendingInvites :many
SELECT i.*, u.email AS created_by_email
FROM invites i
LEFT JOIN users u ON u.id = i.created_by
WHERE i.project_id = $1
  AND i.accepted_at IS NULL AND i.revoked_at IS NULL AND i.expires_at > NOW()
ORDER BY i.created_at DESC, i.id DESC;

-- name: GetPendingInvite :one
SELECT * FROM invites
WHERE id = $1 AND project_id = $2
  AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > NOW();

-- name: RevokeInvite :one
UPDATE invites SET revoked_at = NOW()
WHERE id = $1 AND project_id = $2
  AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > NOW()
RETURNING *;

-- name: LookupInvite :one
-- What the accept page may show to whoever holds the link: the project name,
-- the role and the address the invite is bound to.
SELECT i.role, i.email, p.name AS project_name
FROM invites i
JOIN projects p ON p.id = i.project_id
WHERE i.token_hash = $1
  AND i.accepted_at IS NULL AND i.revoked_at IS NULL AND i.expires_at > NOW();

-- name: ClaimInvite :one
-- Marks the invite used. Of two requests with the same link only one gets a
-- row back; the other waits for the first to commit and then finds it used.
UPDATE invites SET accepted_at = NOW()
WHERE token_hash = $1
  AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > NOW()
RETURNING *;

-- name: SetInviteAcceptedBy :exec
UPDATE invites SET accepted_by = $2 WHERE id = $1;

-- name: AddInvitedMember :one
-- Adds the person to the project, and keeps a stronger role they already hold.
INSERT INTO project_members (project_id, user_id, role)
VALUES ($1, $2, $3)
ON CONFLICT (project_id, user_id) DO UPDATE SET role = CASE
    WHEN (CASE project_members.role WHEN 'admin' THEN 3 WHEN 'manager' THEN 2 ELSE 1 END)
         >= (CASE EXCLUDED.role WHEN 'admin' THEN 3 WHEN 'manager' THEN 2 ELSE 1 END)
    THEN project_members.role
    ELSE EXCLUDED.role
END
RETURNING *;

-- name: GetProjectSlugByID :one
SELECT slug FROM projects WHERE id = $1;
