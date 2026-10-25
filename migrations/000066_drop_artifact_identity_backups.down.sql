-- Recreate the backup tables empty so the 000062 down migration, which reads
-- them, still runs. The rows they held are not recoverable, so rolling back
-- 000062 afterwards restores only the NULL-distinct unique key.
CREATE TABLE IF NOT EXISTS migration_000062_artifacts (
    LIKE artifacts,
    survivor_id UUID
);

CREATE TABLE IF NOT EXISTS migration_000062_artifact_refs (
    table_name TEXT NOT NULL,
    row_id UUID NOT NULL,
    artifact_id UUID NOT NULL
);
