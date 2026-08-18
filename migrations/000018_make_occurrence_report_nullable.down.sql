-- Reverse 000018: occurrences must reference a report again. Watcher
-- occurrences (NULL report_id) must be removed before this can apply.
ALTER TABLE finding_occurrences ALTER COLUMN report_id SET NOT NULL;
