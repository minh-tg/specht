-- name: ExpireWaivers :many
UPDATE waivers SET
    enabled = false,
    updated_at = NOW()
WHERE enabled = true AND expires_at IS NOT NULL AND expires_at <= NOW()
RETURNING id, project_id, name;
