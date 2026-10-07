ALTER TABLE project_members DROP CONSTRAINT IF EXISTS project_members_role_check;
ALTER TABLE project_teams DROP CONSTRAINT IF EXISTS project_teams_role_check;

UPDATE project_members SET role = 'editor' WHERE role = 'manager';
UPDATE project_members SET role = 'viewer' WHERE role = 'member';

UPDATE project_teams SET role = 'editor' WHERE role = 'manager';
UPDATE project_teams SET role = 'viewer' WHERE role = 'member';

ALTER TABLE project_members
    ADD CONSTRAINT project_members_role_check CHECK (role IN ('admin', 'editor', 'viewer'));

ALTER TABLE project_teams
    ADD CONSTRAINT project_teams_role_check CHECK (role IN ('admin', 'editor', 'viewer'));

ALTER TABLE project_members ALTER COLUMN role SET DEFAULT 'viewer';
