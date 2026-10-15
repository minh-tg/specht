-- name: CreateWaiver :one
-- An empty status defaults to approved, so direct creation by a manager or
-- admin keeps working; a member's request passes pending and the requester.
INSERT INTO waivers (project_id, name, description, enabled, expires_at, status, reason, requested_by, requested_at)
VALUES (
    $1, $2, $3, $4, $5,
    COALESCE(NULLIF(sqlc.arg(status)::text, ''), 'approved'),
    sqlc.arg(reason)::text,
    sqlc.narg(requested_by)::uuid,
    sqlc.narg(requested_at)::timestamptz
)
RETURNING *;

-- name: DecideWaiver :one
-- Moves a pending waiver to a final status. No row comes back when the
-- waiver is missing or no longer pending; the caller tells the two apart.
UPDATE waivers SET
    status = sqlc.arg(status)::text,
    decided_by = sqlc.narg(decided_by)::uuid,
    decided_at = NOW(),
    decision_note = sqlc.arg(decision_note)::text,
    updated_at = NOW()
WHERE id = $1 AND project_id = $2 AND status = 'pending'
RETURNING *;

-- name: ListWaivers :many
SELECT * FROM waivers
WHERE project_id = $1
ORDER BY created_at DESC, id DESC;

-- name: GetWaiver :one
SELECT * FROM waivers
WHERE id = $1 AND project_id = $2;

-- name: UpdateWaiver :one
-- set_expires selects whether expires_at is written: true binds the new
-- value (NULL clears it), false leaves the stored expiry untouched.
UPDATE waivers SET
    name = COALESCE($3, name),
    description = COALESCE($4, description),
    expires_at = CASE WHEN sqlc.arg(set_expires)::boolean
        THEN sqlc.arg(expires_at)::timestamptz ELSE expires_at END,
    updated_at = NOW()
WHERE id = $1 AND project_id = $2
RETURNING *;

-- name: DeleteWaiver :one
DELETE FROM waivers
WHERE id = $1 AND project_id = $2
RETURNING *;

-- name: ToggleWaiver :one
-- Only an approved waiver flips, and a disabled one comes back on only while
-- its expiry has not passed. No row comes back otherwise; the caller reads the
-- waiver to tell a missing row from a refused flip.
UPDATE waivers SET
    enabled = NOT enabled,
    updated_at = NOW()
WHERE id = $1 AND project_id = $2
  AND status = 'approved'
  AND (enabled OR expires_at IS NULL OR expires_at > NOW())
RETURNING *;

-- name: SetWaiverEnabled :one
-- Idempotent enable or disable of an approved waiver. A row comes back only
-- when the flag actually changes, so a repeated call writes nothing. Enabling
-- needs an unexpired waiver, and a non-null expected_updated_at makes the
-- write conditional on the version the caller saw. No row comes back when any
-- condition fails; the caller reads the waiver to say which one.
UPDATE waivers SET
    enabled = sqlc.arg(enabled)::boolean,
    updated_at = NOW()
WHERE id = $1 AND project_id = $2
  AND status = 'approved'
  AND enabled <> sqlc.arg(enabled)::boolean
  AND (NOT sqlc.arg(enabled)::boolean OR expires_at IS NULL OR expires_at > NOW())
  AND (sqlc.narg(expected_updated_at)::timestamptz IS NULL
       OR updated_at = sqlc.narg(expected_updated_at)::timestamptz)
RETURNING *;

-- name: ListActiveWaivers :many
SELECT * FROM waivers
WHERE project_id = $1
  AND status = 'approved'
  AND enabled = true
  AND (expires_at IS NULL OR expires_at > NOW())
ORDER BY created_at DESC, id DESC;

-- name: RefreshWaiverScopeAll :one
-- A waiver with no contexts, targets or conditions covers every finding.
-- Recompute the flag after the child rows of a create or update are written.
UPDATE waivers w SET scope_all = (
    NOT EXISTS (SELECT 1 FROM waiver_conditions c WHERE c.waiver_id = w.id)
    AND NOT EXISTS (SELECT 1 FROM waiver_contexts x WHERE x.waiver_id = w.id)
    AND NOT EXISTS (SELECT 1 FROM waiver_finding_targets t WHERE t.waiver_id = w.id)
)
WHERE w.id = $1
RETURNING *;

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

-- name: ListWaiverConditionsByWaiverIDs :many
SELECT * FROM waiver_conditions
WHERE waiver_id = ANY($1::uuid[])
ORDER BY created_at;

-- name: ListWaiverContextsByWaiverIDs :many
SELECT * FROM waiver_contexts
WHERE waiver_id = ANY($1::uuid[])
ORDER BY created_at;

-- name: ListWaiverFindingTargetsByWaiverIDs :many
SELECT * FROM waiver_finding_targets
WHERE waiver_id = ANY($1::uuid[])
ORDER BY created_at;
