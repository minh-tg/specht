CREATE INDEX idx_reports_latest_completed
    ON reports (project_id, (COALESCE(completed_at, created_at)) DESC, created_at DESC, id DESC)
    WHERE status = 'completed';
