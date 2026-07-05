-- name: UpsertTarget :one
INSERT INTO targets (project_id, name, kind, locator)
VALUES ($1, $2, $3, $4)
ON CONFLICT (project_id, name)
DO UPDATE SET
    kind = EXCLUDED.kind,
    locator = EXCLUDED.locator
RETURNING *;

-- name: ListTargets :many
SELECT * FROM targets
WHERE project_id = $1
ORDER BY name;

-- name: GetTarget :one
SELECT * FROM targets
WHERE id = $1 AND project_id = $2
LIMIT 1;

-- name: DeleteTarget :one
DELETE FROM targets
WHERE id = $1 AND project_id = $2
RETURNING *;
