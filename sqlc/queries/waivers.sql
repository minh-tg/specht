-- name: CreateWaiver :one
INSERT INTO waivers (project_id, name, description, enabled)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: ListWaivers :many
SELECT * FROM waivers
WHERE project_id = $1
ORDER BY created_at DESC;

-- name: GetWaiver :one
SELECT * FROM waivers
WHERE id = $1 AND project_id = $2;

-- name: UpdateWaiver :one
UPDATE waivers SET
    name = COALESCE($3, name),
    description = COALESCE($4, description),
    updated_at = NOW()
WHERE id = $1 AND project_id = $2
RETURNING *;

-- name: DeleteWaiver :one
DELETE FROM waivers
WHERE id = $1 AND project_id = $2
RETURNING *;

-- name: ToggleWaiver :one
UPDATE waivers SET
    enabled = NOT enabled,
    updated_at = NOW()
WHERE id = $1 AND project_id = $2
RETURNING *;

-- name: ListActiveWaivers :many
SELECT * FROM waivers
WHERE project_id = $1 AND enabled = true
ORDER BY created_at DESC;

-- name: CreateWaiverCondition :one
INSERT INTO waiver_conditions (waiver_id, field, operator, value)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: ListWaiverConditions :many
SELECT * FROM waiver_conditions
WHERE waiver_id = $1
ORDER BY created_at;

-- name: DeleteWaiverConditions :exec
DELETE FROM waiver_conditions WHERE waiver_id = $1;

-- name: CreateWaiverContext :one
INSERT INTO waiver_contexts (waiver_id, environment_id, target_id, artifact_id)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: ListWaiverContexts :many
SELECT * FROM waiver_contexts
WHERE waiver_id = $1
ORDER BY created_at;

-- name: DeleteWaiverContexts :exec
DELETE FROM waiver_contexts WHERE waiver_id = $1;

-- name: CreateWaiverFindingTarget :one
INSERT INTO waiver_finding_targets (waiver_id, finding_id)
VALUES ($1, $2)
RETURNING *;

-- name: ListWaiverFindingTargets :many
SELECT * FROM waiver_finding_targets
WHERE waiver_id = $1
ORDER BY created_at;

-- name: DeleteWaiverFindingTargets :exec
DELETE FROM waiver_finding_targets WHERE waiver_id = $1;

-- name: CreateWaiverEvent :one
INSERT INTO waiver_events (waiver_id, event_type, actor_id, metadata)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: ListWaiverEvents :many
SELECT * FROM waiver_events
WHERE waiver_id = $1
ORDER BY created_at DESC;
