-- reachability as a four-state assessment (reachable,
-- not_reachable, unknown, not_applicable) instead of a raw boolean.
-- Existing rows are migrated: reachable=true -> 'reachable',
-- reachable=false -> 'not_reachable'.

CREATE TYPE reachability_state AS ENUM (
    'reachable',
    'not_reachable',
    'unknown',
    'not_applicable'
);

ALTER TABLE reachability_assessments
    ADD COLUMN state reachability_state NOT NULL DEFAULT 'unknown';

UPDATE reachability_assessments
SET state = CASE WHEN reachable THEN 'reachable'::reachability_state
                 ELSE 'not_reachable'::reachability_state
            END;

ALTER TABLE reachability_assessments
    DROP COLUMN reachable;
