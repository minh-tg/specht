-- name: ListProjects :many
SELECT * FROM projects
ORDER BY created_at DESC, id DESC;

-- name: ListProjectsByIDs :many
SELECT * FROM projects
WHERE id = ANY($1::uuid[])
ORDER BY created_at DESC, id DESC;

-- name: GetProjectBySlug :one
SELECT * FROM projects
WHERE slug = $1 LIMIT 1;

-- name: GetProjectByID :one
SELECT * FROM projects
WHERE id = $1 LIMIT 1;

-- name: CreateProject :one
INSERT INTO projects (slug, name, description, deployment_threshold, settings)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: UpdateProject :one
UPDATE projects SET name = $2, description = $3, updated_at = NOW()
WHERE slug = $1
RETURNING *;

-- name: UpdateProjectSettings :one
UPDATE projects SET settings = $2, updated_at = NOW()
WHERE id = $1
RETURNING *;

-- name: DeleteProject :one
DELETE FROM projects WHERE slug = $1
RETURNING *;

-- name: UpsertProjectMember :one
INSERT INTO project_members (project_id, user_id, role)
VALUES ($1, $2, $3)
ON CONFLICT (project_id, user_id) DO UPDATE SET role = EXCLUDED.role
RETURNING *;

-- name: ListProjectMembers :many
SELECT * FROM project_members
WHERE project_id = $1
ORDER BY created_at ASC, user_id ASC;

-- name: ListProjectMembersWithUsers :many
-- The roster with each person's email and display name, so a screen shows who a
-- member is without asking the admin-only user directory.
SELECT pm.project_id, pm.user_id, pm.role, pm.created_at, u.email, u.display_name
FROM project_members pm
JOIN users u ON u.id = pm.user_id
WHERE pm.project_id = $1
ORDER BY pm.created_at ASC, pm.user_id ASC;

-- name: IsProjectMember :one
SELECT EXISTS(SELECT 1 FROM project_members WHERE project_id = $1 AND user_id = $2);

-- name: ListMemberProjectIDs :many
SELECT project_id FROM project_members WHERE user_id = $1;

-- name: GetProjectMember :one
SELECT * FROM project_members
WHERE project_id = $1 AND user_id = $2;

-- name: DeleteProjectMember :exec
DELETE FROM project_members
WHERE project_id = $1 AND user_id = $2;

-- name: LockProjectForMembership :one
SELECT id FROM projects
WHERE id = $1
FOR NO KEY UPDATE;

-- name: LockProjectsAdministeredBy :many
-- Takes the membership lock of every project where the user holds an admin
-- row, in id order so two callers cannot wait on each other. A deactivation
-- holds them while it checks for projects it would leave without an admin, so
-- a concurrent removal or deactivation of the other admin waits for it.
SELECT p.id FROM projects p
WHERE p.id IN (SELECT pm.project_id FROM project_members pm WHERE pm.user_id = $1 AND pm.role = 'admin')
ORDER BY p.id
FOR NO KEY UPDATE OF p;

-- name: CountProjectAdmins :one
-- Admins who can sign in: a deactivated account holds a row but governs nothing.
SELECT COUNT(*) FROM project_members pm
JOIN users u ON u.id = pm.user_id AND u.disabled_at IS NULL
WHERE pm.project_id = $1 AND pm.role = 'admin';

-- name: CountOtherProjectAdmins :one
-- Active admins besides one user, the number the last-admin guard needs when
-- that user is about to be removed or demoted.
SELECT COUNT(*) FROM project_members pm
JOIN users u ON u.id = pm.user_id AND u.disabled_at IS NULL
WHERE pm.project_id = $1 AND pm.role = 'admin' AND pm.user_id <> $2;

-- name: ListProjectsSoleAdminedBy :many
-- Slugs of the projects where one active user is the only active admin.
SELECT p.slug FROM projects p
JOIN project_members me ON me.project_id = p.id AND me.user_id = $1 AND me.role = 'admin'
JOIN users mu ON mu.id = me.user_id AND mu.disabled_at IS NULL
WHERE NOT EXISTS (
    SELECT 1 FROM project_members pm
    JOIN users u ON u.id = pm.user_id AND u.disabled_at IS NULL
    WHERE pm.project_id = p.id AND pm.role = 'admin' AND pm.user_id <> $1
)
ORDER BY p.slug;
