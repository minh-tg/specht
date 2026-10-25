-- Drop the backup tables 000062 kept while it merged digest-less duplicate
-- artifacts. After this the merge cannot be undone from the database: the
-- merged-away rows and the reports / waiver_contexts references that pointed at
-- them are gone. Retention of the backups ends with this migration.
DROP TABLE IF EXISTS migration_000062_artifact_refs;
DROP TABLE IF EXISTS migration_000062_artifacts;
