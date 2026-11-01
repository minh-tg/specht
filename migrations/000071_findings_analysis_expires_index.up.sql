-- The analysis expiry sweep selects findings by analysis_expires_at every
-- SWEEP_INTERVAL. Without an index each run scans the whole findings table.
-- The partial index holds only rows with an expiry set. The file holds this
-- one statement so the migration driver runs it outside a transaction, which
-- CONCURRENTLY requires; writes to findings are not blocked while it builds.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_findings_analysis_expires_at
    ON findings (analysis_expires_at)
    WHERE analysis_expires_at IS NOT NULL;
