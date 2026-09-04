-- Fix: per-project watcher watermark so disabling a project cannot silently
-- lose advisories. The previous single-row watcher_state (id=1) meant one
-- global watermark: if project A was disabled while enabled project B
-- advanced the shared watermark, re-enabling A excluded advisories published
-- during its disabled period. A per-project watermark means each project's
-- cutoff reflects only its own poll history; a disabled project's watermark
-- simply stops advancing, so on re-enable its next poll is a catch-up from
-- its own last poll (cold start if it never polled).
--
-- The legacy global row is kept for status reporting; per-project rows are
-- authoritative for poll cutoffs.

CREATE TABLE IF NOT EXISTS watcher_project_state (
    project_id UUID PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
    last_successful_poll_at TIMESTAMPTZ
);

-- Backfill only projects that remain enabled. Disabled projects have no
-- historical per-project watermark and therefore catch up from the configured
-- cold-start policy when they are enabled again.
INSERT INTO watcher_project_state (project_id, last_successful_poll_at)
SELECT p.id, w.last_successful_poll_at
FROM projects p
CROSS JOIN watcher_state w
WHERE w.id = 1 AND p.cve_watcher_enabled
ON CONFLICT (project_id) DO NOTHING;
