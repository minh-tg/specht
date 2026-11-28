-- The Needs you list and the navigation badge select a person's open findings by assignee_id on
-- every page load. Without an index each fetch scans every finding of the person's projects. Most
-- findings have no assignee, so the partial index holds only the assigned ones. The file holds
-- this one statement so the migration driver runs it outside a transaction, which CONCURRENTLY
-- requires; writes to findings are not blocked while it builds.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_findings_assignee_id
    ON findings (assignee_id)
    WHERE assignee_id IS NOT NULL;
