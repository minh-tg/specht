-- Migration 57 made waiver_deletions refuse UPDATE only. A DELETE or TRUNCATE
-- with the application's own database role still erased the record of a deleted
-- waiver. Both are refused now.
--
-- Deleting a project still removes its records: the foreign key cascade deletes
-- them after the project row is gone, and the row trigger lets a delete through
-- only when the project no longer exists. A plain DELETE while the project
-- exists, and any TRUNCATE (including one cascading from projects), is refused.
CREATE FUNCTION waiver_deletions_refuse_delete() RETURNS trigger AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM projects WHERE id = OLD.project_id) THEN
        RAISE EXCEPTION 'waiver_deletions is append-only';
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER waiver_deletions_no_delete
    BEFORE DELETE ON waiver_deletions
    FOR EACH ROW EXECUTE FUNCTION waiver_deletions_refuse_delete();

CREATE FUNCTION waiver_deletions_refuse_truncate() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'waiver_deletions is append-only';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER waiver_deletions_no_truncate
    BEFORE TRUNCATE ON waiver_deletions
    FOR EACH STATEMENT EXECUTE FUNCTION waiver_deletions_refuse_truncate();
