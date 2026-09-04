-- watcher health/status visibility + per-project enable/interval
-- configuration.
--
-- watcher_state gains attempt/error tracking so operators can see whether
-- the watcher is healthy (last successful poll) or failing (consecutive
-- failures, last error, last attempt) — a failed or stale watcher must not
-- be mistaken for a clean result.
--
-- projects gains per-project watcher enable + interval overrides so a team
-- can schedule monitoring with explicit scope and ownership.

ALTER TABLE watcher_state
    ADD COLUMN last_poll_attempt_at TIMESTAMPTZ,
    ADD COLUMN last_error TEXT,
    ADD COLUMN consecutive_failures INT NOT NULL DEFAULT 0;

ALTER TABLE projects
    ADD COLUMN cve_watcher_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN cve_watcher_interval_seconds INT NOT NULL DEFAULT 3600;
