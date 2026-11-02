-- The branch the project treats as its trunk. Reports on it serve as the
-- baseline for the introduced-only gate even when the branch was once the head
-- of a pull request. NULL means unset: the server then decides from the
-- branch's own reports.
ALTER TABLE projects
    ADD COLUMN default_branch TEXT,
    ADD CONSTRAINT projects_default_branch_check CHECK (
        default_branch IS NULL OR (
            length(default_branch) BETWEEN 1 AND 255
            AND default_branch = btrim(default_branch)
        )
    );
