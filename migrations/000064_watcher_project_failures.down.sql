-- down: drop the per-project watcher failure columns added in 000064.

ALTER TABLE watcher_project_state
    DROP COLUMN IF EXISTS last_error,
    DROP COLUMN IF EXISTS consecutive_failures;
