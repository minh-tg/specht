-- name: ClaimExpiringWaivers :many
-- Claims the approved waivers that end before the given time and have not been
-- announced yet, so each is announced once however many servers sweep.
UPDATE waivers SET expiry_warned_at = NOW()
WHERE enabled = true
  AND status = 'approved'
  AND expires_at IS NOT NULL
  AND expires_at > NOW()
  AND expires_at <= sqlc.arg(ending_before)::timestamptz
  AND expiry_warned_at IS NULL
RETURNING id, project_id, name, expires_at;

-- name: CountExpiringWaivers :one
-- Approved waivers of a project that end before the given time.
SELECT COUNT(*)::int FROM waivers
WHERE project_id = $1
  AND enabled = true
  AND status = 'approved'
  AND expires_at IS NOT NULL
  AND expires_at > NOW()
  AND expires_at <= sqlc.arg(ending_before)::timestamptz;

-- name: ExpireWaivers :many
-- Disables expired approved waivers. A pending request that outlives its
-- expiry can no longer be approved, so it is rejected with a note instead.
-- The returned status tells the caller which of the two happened.
UPDATE waivers SET
    enabled = false,
    status = CASE WHEN status = 'pending' THEN 'rejected' ELSE status END,
    decision_note = CASE WHEN status = 'pending' THEN 'expired before a decision' ELSE decision_note END,
    decision_reason = CASE WHEN status = 'pending' THEN 'expired' ELSE decision_reason END,
    decided_at = CASE WHEN status = 'pending' THEN NOW() ELSE decided_at END,
    updated_at = NOW()
WHERE enabled = true
  AND status IN ('approved', 'pending')
  AND expires_at IS NOT NULL
  AND expires_at <= NOW()
RETURNING id, project_id, name, status;
