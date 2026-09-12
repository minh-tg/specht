-- name: ListProjects :many
SELECT * FROM projects
ORDER BY created_at DESC;

-- name: GetProjectBySlug :one
SELECT * FROM projects
WHERE slug = $1 LIMIT 1;

-- name: CreateProject :one
INSERT INTO projects (slug, name, description, deployment_threshold, settings)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: UpdateProject :one
UPDATE projects SET name = $2, description = $3, updated_at = NOW()
WHERE slug = $1
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
ORDER BY created_at ASC;

-- name: IsProjectMember :one
SELECT EXISTS(SELECT 1 FROM project_members WHERE project_id = $1 AND user_id = $2);

-- name: ListMemberProjectIDs :many
SELECT project_id FROM project_members WHERE user_id = $1;
