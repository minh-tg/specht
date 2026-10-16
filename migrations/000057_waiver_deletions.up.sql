-- Deleting a waiver removes its conditions, contexts, targets and events with
-- it. This table keeps what the waiver was at the moment of the delete: the
-- row, its scope and its full event trail, plus who deleted it and when. The
-- application only inserts into it, and a trigger refuses updates, so the
-- record outlives the waiver. Deleting the project removes its records too.
--
-- Every column but the snapshot has a default, and nothing else reads the
-- table, so the previous release keeps working against this schema.
CREATE TABLE waiver_deletions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    waiver_id UUID NOT NULL,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    deleted_by TEXT,
    deleted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    snapshot JSONB NOT NULL DEFAULT '{}'
);

CREATE INDEX idx_waiver_deletions_project ON waiver_deletions (project_id, deleted_at DESC);
CREATE INDEX idx_waiver_deletions_waiver ON waiver_deletions (waiver_id);

CREATE FUNCTION waiver_deletions_refuse_update() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'waiver_deletions is append-only';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER waiver_deletions_append_only
    BEFORE UPDATE ON waiver_deletions
    FOR EACH ROW EXECUTE FUNCTION waiver_deletions_refuse_update();
