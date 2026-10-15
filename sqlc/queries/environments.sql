-- name: EnsureEnvironment :one
-- Creates the environment with the given defaults, or returns the existing
-- row untouched, so a later scan never resets what a person has edited.
INSERT INTO environments (project_id, name, tier, internet_facing, data_sensitivity)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (project_id, name)
DO UPDATE SET name = environments.name
RETURNING *;

-- name: ListEnvironments :many
SELECT * FROM environments
WHERE project_id = $1
ORDER BY name;

-- name: GetEnvironment :one
SELECT * FROM environments
WHERE id = $1 AND project_id = $2
LIMIT 1;

-- name: DeleteEnvironment :one
DELETE FROM environments
WHERE id = $1 AND project_id = $2
RETURNING *;
