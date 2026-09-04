-- name: GetWatcherState :one
-- The single-row watcher_state table (migration 000017; id = 1 enforced by
-- CHECK). Returns pgx.ErrNoRows when no poll has ever completed — the
-- daemon treats that as the cold-start condition.
SELECT id, last_successful_poll_at, last_poll_attempt_at, last_error, consecutive_failures
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

-- name: RecordWatcherAttempt :exec
-- Records that a poll attempt started (or a failure occurred). On failure
-- the error and consecutive-failure counter are set; on success the caller
-- follows with UpdateWatcherState, and ResetWatcherFailure clears the error
-- state. Used for operator visibility into watcher health.
INSERT INTO watcher_state (id, last_poll_attempt_at, last_error, consecutive_failures)
VALUES (1, $1::timestamptz, $2, $3)
ON CONFLICT (id) DO UPDATE SET
    last_poll_attempt_at = EXCLUDED.last_poll_attempt_at;

-- name: ResetWatcherFailure :exec
-- Clears the error state after a successful poll, keeping the attempt time.
UPDATE watcher_state
SET last_error = NULL, consecutive_failures = 0
WHERE id = 1;

-- name: IncrementWatcherFailure :exec
-- Bumps the consecutive-failure counter and records the error. Upserts so a
-- failure before any successful poll (no row yet) still records state.
INSERT INTO watcher_state (id, last_poll_attempt_at, last_error, consecutive_failures)
VALUES (1, $2::timestamptz, $1, 1)
ON CONFLICT (id) DO UPDATE SET
    consecutive_failures = watcher_state.consecutive_failures + 1,
    last_error = EXCLUDED.last_error,
    last_poll_attempt_at = EXCLUDED.last_poll_attempt_at;

-- name: GetProjectWatcherConfig :one
-- Per-project CVE watcher enable + interval override (migration 000020).
SELECT id, slug, name, cve_watcher_enabled, cve_watcher_interval_seconds
FROM projects
WHERE id = $1;

-- name: GetProjectWatcherState :one
-- A project's own watcher watermark (per-project cutoff so disabling a
-- project cannot lose advisories). Returns pgx.ErrNoRows when the project
-- has never polled (cold start / catch-up from full history).
SELECT project_id, last_successful_poll_at
FROM watcher_project_state
WHERE project_id = $1;

-- name: UpsertProjectWatcherState :exec
-- Advances one project's watermark after a fully successful poll of that
-- project's inventory.
INSERT INTO watcher_project_state (project_id, last_successful_poll_at)
VALUES ($1, $2::timestamptz)
ON CONFLICT (project_id) DO UPDATE SET
    last_successful_poll_at = EXCLUDED.last_successful_poll_at;
