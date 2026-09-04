-- Fix: LatestReachabilityByFinding must reflect the most recent assessment
-- update, not the row's original created_at (an upsert updates state/evidence
-- without changing created_at, so ordering by created_at could report a stale
-- assessment as "latest"). Add updated_at, maintained on every upsert.

ALTER TABLE reachability_assessments
    ADD COLUMN updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- Backfill: existing rows' updated_at = created_at (they have never been
-- updated since the column did not exist).
UPDATE reachability_assessments SET updated_at = created_at;
