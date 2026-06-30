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
