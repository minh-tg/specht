-- Owner records who is responsible for a scan target (team name, service
-- owner, or repository owner slug). It is free-text until the -- repository-provider decision gives it a structured identity; ingest binds
-- it to the target row so every finding observed under that target inherits
-- traceable ownership. Last supplied value wins; absent input preserves the
-- stored value (see UpsertTarget).
ALTER TABLE targets ADD COLUMN IF NOT EXISTS owner TEXT;
