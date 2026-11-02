ALTER TABLE projects
    DROP CONSTRAINT IF EXISTS projects_default_branch_check,
    DROP COLUMN IF EXISTS default_branch;
