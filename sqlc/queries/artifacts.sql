-- name: UpsertArtifact :one
INSERT INTO artifacts (project_id, target_id, artifact_type, name, version, digest, locator, metadata)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (project_id, artifact_type, name, digest)
DO UPDATE SET
    target_id = EXCLUDED.target_id,
    version = EXCLUDED.version,
    locator = EXCLUDED.locator,
    metadata = EXCLUDED.metadata
RETURNING *;

-- name: ListArtifacts :many
SELECT * FROM artifacts
WHERE project_id = $1
ORDER BY name;

-- name: ListArtifactsByTarget :many
SELECT * FROM artifacts
WHERE target_id = $1
ORDER BY name;

-- name: GetArtifact :one
SELECT * FROM artifacts
WHERE id = $1 AND project_id = $2
LIMIT 1;

-- name: DeleteArtifact :one
DELETE FROM artifacts
WHERE id = $1 AND project_id = $2
RETURNING *;
