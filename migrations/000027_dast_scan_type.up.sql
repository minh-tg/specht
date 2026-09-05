-- DAST reports scan deployments, not source trees: allow the scan type.
ALTER TABLE reports DROP CONSTRAINT IF EXISTS reports_scan_type_check;
ALTER TABLE reports ADD CHECK (scan_type IN (
    'image', 'filesystem', 'repository', 'sbom', 'sarif', 'iac', 'lockfile', 'dast'
));
