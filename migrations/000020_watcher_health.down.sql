-- down: drop the watcher health/status and per-project config
-- columns added in 000020.

ALTER TABLE projects
    DROP COLUMN IF EXISTS cve_watcher_interval_seconds,
    DROP COLUMN IF EXISTS cve_watcher_enabled;

ALTER TABLE watcher_state
    DROP COLUMN IF EXISTS consecutive_failures,
    DROP COLUMN IF EXISTS last_error,
    DROP COLUMN IF EXISTS last_poll_attempt_at;
