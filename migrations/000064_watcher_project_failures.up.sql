-- Per-project watcher failure state. watcher_state holds one global
-- failure counter, and the daemon skips its reset while any project's poll
-- is failing, so one project stuck on an OSV error made every project's
-- watcher panel read "failing". Each project now carries its own counter
-- and last error; a successful poll of that project clears them.

ALTER TABLE watcher_project_state
    ADD COLUMN consecutive_failures INT NOT NULL DEFAULT 0,
    ADD COLUMN last_error TEXT;
