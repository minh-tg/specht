-- name: EnsureInstanceSecret :one
-- Stores the value when the name is new and returns whatever is stored, in one
-- statement, so callers racing on first use all end up with the same value.
INSERT INTO instance_secrets (name, value)
VALUES ($1, $2)
ON CONFLICT (name) DO UPDATE SET name = instance_secrets.name
RETURNING value;
