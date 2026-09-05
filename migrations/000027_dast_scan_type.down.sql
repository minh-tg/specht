-- Restore the pre-DAST scan_type set. Fails if dast reports exist.
ALTER TABLE reports DROP CONSTRAINT IF EXISTS reports_scan_type_check;
ALTER TABLE reports ADD CHECK (scan_type IN (
    'image', 'filesystem', 'repository', 'sbom', 'sarif', 'iac', 'lockfile'
));
