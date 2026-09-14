-- name: CreatePolicyTemplate :one
INSERT INTO policy_templates (name, description, definition)
VALUES ($1, $2, $3)
RETURNING *;

-- name: GetPolicyTemplateByID :one
SELECT * FROM policy_templates WHERE id = $1;

-- name: GetPolicyTemplateByName :one
SELECT * FROM policy_templates WHERE name = $1;

-- name: ListPolicyTemplates :many
SELECT * FROM policy_templates
ORDER BY name ASC;

-- name: UpdatePolicyTemplate :one
-- Definition replacement bumps the version so consumers can tell a
-- baseline moved underneath them; name changes ride the same row.
UPDATE policy_templates SET
    name = $2,
    description = $3,
    definition = $4,
    version = version + 1,
    updated_at = NOW()
WHERE id = $1
RETURNING *;

-- name: DeletePolicyTemplate :exec
DELETE FROM policy_templates WHERE id = $1;

-- name: SetProjectPolicyTemplate :one
UPDATE projects SET
    policy_template_id = $2,
    updated_at = NOW()
WHERE id = $1
RETURNING *;
