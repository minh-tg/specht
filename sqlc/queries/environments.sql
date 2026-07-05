-- name: UpsertEnvironment :one
INSERT INTO environments (project_id, name, tier, internet_facing, data_sensitivity)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (project_id, name)
DO UPDATE SET
    tier = EXCLUDED.tier,
    internet_facing = EXCLUDED.internet_facing,
    data_sensitivity = EXCLUDED.data_sensitivity
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
