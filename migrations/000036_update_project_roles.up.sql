ALTER TABLE project_members DROP CONSTRAINT IF EXISTS project_members_role_check;
ALTER TABLE project_teams DROP CONSTRAINT IF EXISTS project_teams_role_check;

UPDATE project_members SET role = 'manager' WHERE role = 'editor';
UPDATE project_members SET role = 'member' WHERE role = 'viewer';

UPDATE project_teams SET role = 'manager' WHERE role = 'editor';
UPDATE project_teams SET role = 'member' WHERE role = 'viewer';

ALTER TABLE project_members
    ADD CONSTRAINT project_members_role_check CHECK (role IN ('admin', 'manager', 'member'));

ALTER TABLE project_teams
    ADD CONSTRAINT project_teams_role_check CHECK (role IN ('admin', 'manager', 'member'));

ALTER TABLE project_members ALTER COLUMN role SET DEFAULT 'member';
