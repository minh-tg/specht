-- down: restore the boolean column, mapping the four states back.
-- 'reachable' -> true; every other state ('not_reachable', 'unknown',
-- 'not_applicable') -> false, since the boolean could not express them.

ALTER TABLE reachability_assessments
    ADD COLUMN reachable BOOLEAN;

UPDATE reachability_assessments
SET reachable = (state = 'reachable');

ALTER TABLE reachability_assessments
    ALTER COLUMN reachable SET NOT NULL;

ALTER TABLE reachability_assessments
    DROP COLUMN state;

DROP TYPE IF EXISTS reachability_state;
