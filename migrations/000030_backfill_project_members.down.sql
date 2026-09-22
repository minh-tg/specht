-- Backfill rollback: remove only the viewer rows this migration
-- could have inserted. Rows upgraded to editor/admin afterwards are kept.
DELETE FROM project_members WHERE role = 'viewer';
