-- A project's verdict answers for its default branch, so a finding seen only
-- on change branches must stay out of it. This function names those branches.
--
-- A finding's current sightings are its finding_scope_severities rows: a clean
-- scan of a scope retires that scope's row. A row is off the default branch when
-- its report names a branch and that branch is a change, by the same rule ingest
-- applies when it classifies a report (isChangeReport). With a default branch
-- set, that is any other branch, or the default branch sent with another base.
-- Without one, it is a branch that some report sent with another base.
--
-- An empty result means the finding counts toward the verdict. The function
-- fails closed: a finding with no rows, a row whose report was deleted, a watcher
-- row, or a report without a branch cannot prove it is off the default branch.
CREATE FUNCTION finding_change_branches(p_finding_id UUID)
RETURNS TEXT[]
LANGUAGE sql
STABLE
AS $$
    SELECT CASE
        WHEN bool_and(sighting.off_default) THEN array_agg(DISTINCT sighting.branch ORDER BY sighting.branch)
        ELSE '{}'::TEXT[]
    END
    FROM (
        SELECT
            r.branch,
            COALESCE(
                r.id IS NOT NULL
                AND COALESCE(r.branch, '') <> ''
                AND CASE
                    WHEN COALESCE(p.default_branch, '') <> '' THEN
                        r.branch <> p.default_branch
                        OR (COALESCE(r.base_revision, '') NOT IN ('', r.branch))
                    ELSE EXISTS (
                        SELECT 1 FROM reports other
                        WHERE other.project_id = r.project_id
                          AND other.branch = r.branch
                          AND COALESCE(other.base_revision, '') NOT IN ('', r.branch)
                    )
                END,
                FALSE
            ) AS off_default
        FROM finding_scope_severities s
        JOIN findings f ON f.id = s.finding_id
        JOIN projects p ON p.id = f.project_id
        LEFT JOIN reports r ON r.id = s.report_id
        WHERE s.finding_id = p_finding_id
    ) sighting;
$$;

CREATE INDEX idx_reports_project_branch_base
    ON reports (project_id, branch)
    WHERE base_revision IS NOT NULL AND base_revision <> '';
