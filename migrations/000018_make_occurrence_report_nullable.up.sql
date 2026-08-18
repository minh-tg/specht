-- Watcher findings (finding_kind 'cve_watcher', seeded by 000017) are created
-- from OSV querybatch responses, not from scan reports: they have no report to
-- reference. The report_id NOT NULL constraint from 000007 is relaxed so a
-- watcher occurrence persists with a NULL report_id. Scan-derived occurrences
-- keep passing a report_id exactly as before.
ALTER TABLE finding_occurrences ALTER COLUMN report_id DROP NOT NULL;
