-- Restore NULL-distinct identity, then put the merged-away rows and the
-- references that pointed at them back from the backups the up migration made.
ALTER TABLE artifacts DROP CONSTRAINT artifacts_project_id_artifact_type_name_digest_key;
ALTER TABLE artifacts
    ADD CONSTRAINT artifacts_project_id_artifact_type_name_digest_key
    UNIQUE (project_id, artifact_type, name, digest);

-- A backed-up row whose project or target is gone since the up migration
-- cannot come back as it was: the project's rows are gone with it, and a
-- missing target is cleared as ON DELETE SET NULL would have.
INSERT INTO artifacts (id, project_id, target_id, artifact_type, name, version, digest, locator, metadata, created_at)
SELECT m.id, m.project_id, t.id, m.artifact_type, m.name, m.version, m.digest, m.locator, m.metadata, m.created_at
FROM migration_000062_artifacts m
JOIN projects p ON p.id = m.project_id
LEFT JOIN targets t ON t.id = m.target_id
ON CONFLICT (id) DO NOTHING;

UPDATE reports r
SET artifact_id = b.artifact_id
FROM migration_000062_artifact_refs b
JOIN artifacts a ON a.id = b.artifact_id
WHERE b.table_name = 'reports' AND r.id = b.row_id;

UPDATE waiver_contexts w
SET artifact_id = b.artifact_id
FROM migration_000062_artifact_refs b
JOIN artifacts a ON a.id = b.artifact_id
WHERE b.table_name = 'waiver_contexts' AND w.id = b.row_id;

DROP TABLE migration_000062_artifact_refs;
DROP TABLE migration_000062_artifacts;
