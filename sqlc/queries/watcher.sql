-- name: GetWatcherState :one
-- The single-row watcher_state table (migration 000017; id = 1 enforced by
-- CHECK). Returns pgx.ErrNoRows when no poll has ever completed — the
-- daemon treats that as the cold-start condition.
SELECT id, last_successful_poll_at
FROM watcher_state
WHERE id = 1;

-- name: UpdateWatcherState :exec
-- Advances the poll watermark. The row is created on the first success (the
-- default id 1 satisfies the CHECK constraint) and updated thereafter. The
-- watermark advances only after a fully successful poll.
INSERT INTO watcher_state (id, last_successful_poll_at)
VALUES (1, $1::timestamptz)
ON CONFLICT (id) DO UPDATE SET
    last_successful_poll_at = EXCLUDED.last_successful_poll_at;
