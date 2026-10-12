DROP INDEX IF EXISTS idx_waivers_project_status;

ALTER TABLE waivers
    DROP COLUMN IF EXISTS decision_note,
    DROP COLUMN IF EXISTS decided_at,
    DROP COLUMN IF EXISTS decided_by,
    DROP COLUMN IF EXISTS requested_at,
    DROP COLUMN IF EXISTS requested_by,
    DROP COLUMN IF EXISTS reason,
    DROP COLUMN IF EXISTS scope_all,
    DROP COLUMN IF EXISTS status;
