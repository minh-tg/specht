-- An artifact without a digest is identified by project, type and name. The
-- original UNIQUE (project_id, artifact_type, name, digest) treats NULL digests
-- as distinct, so every ingest that named an artifact without a digest inserted
-- another row, and a waiver context scoped to one of them stopped matching on
-- the next scan. This migration merges each group of digest-less duplicates
-- into its newest row (the one carrying the latest scan's fields) and makes
-- NULL digests compare equal.
--
-- Backups, kept until a later cleanup migration drops them after the rollback
-- window of the release that ships this one:
--   migration_000062_artifacts      the merged-away rows plus their survivor_id
--   migration_000062_artifact_refs  every reports / waiver_contexts row that
--                                   pointed at a merged-away row, with that id
-- The down migration restores the rows and the references from them.
CREATE TABLE migration_000062_artifacts AS
SELECT a.*, g.survivor_id
FROM artifacts a
JOIN (
    SELECT id,
           first_value(id) OVER (
               PARTITION BY project_id, artifact_type, name
               ORDER BY created_at DESC, id DESC
           ) AS survivor_id
    FROM artifacts
    WHERE digest IS NULL
) g ON g.id = a.id
WHERE g.id <> g.survivor_id;

CREATE TABLE migration_000062_artifact_refs (
    table_name TEXT NOT NULL,
    row_id UUID NOT NULL,
    artifact_id UUID NOT NULL
);

INSERT INTO migration_000062_artifact_refs (table_name, row_id, artifact_id)
SELECT 'reports', r.id, r.artifact_id
FROM reports r
JOIN migration_000062_artifacts m ON m.id = r.artifact_id;

INSERT INTO migration_000062_artifact_refs (table_name, row_id, artifact_id)
SELECT 'waiver_contexts', w.id, w.artifact_id
FROM waiver_contexts w
JOIN migration_000062_artifacts m ON m.id = w.artifact_id;

UPDATE reports r
SET artifact_id = m.survivor_id
FROM migration_000062_artifacts m
WHERE r.artifact_id = m.id;

UPDATE waiver_contexts w
SET artifact_id = m.survivor_id
FROM migration_000062_artifacts m
WHERE w.artifact_id = m.id;

DELETE FROM artifacts a
USING migration_000062_artifacts m
WHERE a.id = m.id;

ALTER TABLE artifacts DROP CONSTRAINT artifacts_project_id_artifact_type_name_digest_key;
ALTER TABLE artifacts
    ADD CONSTRAINT artifacts_project_id_artifact_type_name_digest_key
    UNIQUE NULLS NOT DISTINCT (project_id, artifact_type, name, digest);
