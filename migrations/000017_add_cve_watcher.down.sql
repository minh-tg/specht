ALTER TABLE projects DROP COLUMN IF EXISTS cve_watcher_gate;

DROP TABLE IF EXISTS watcher_state;

DELETE FROM finding_kinds WHERE code = 'cve_watcher';

DROP TABLE IF EXISTS report_packages;
