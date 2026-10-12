-- name: ExpireWaivers :many
-- Disables expired approved waivers. A pending request that outlives its
-- expiry can no longer be approved, so it is rejected with a note instead.
-- The returned status tells the caller which of the two happened.
UPDATE waivers SET
    enabled = false,
    status = CASE WHEN status = 'pending' THEN 'rejected' ELSE status END,
    decision_note = CASE WHEN status = 'pending' THEN 'expired before a decision' ELSE decision_note END,
    decided_at = CASE WHEN status = 'pending' THEN NOW() ELSE decided_at END,
    updated_at = NOW()
WHERE enabled = true
  AND status IN ('approved', 'pending')
  AND expires_at IS NOT NULL
  AND expires_at <= NOW()
RETURNING id, project_id, name, status;
