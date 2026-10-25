-- Per-finding proof that a report looked for a finding, written by parsers
-- whose output lists what they checked (a SARIF rule list, Checkov passed
-- checks). Kind-wide coverage stays in covered_finding_kinds. Keys are
-- 'fp:<fingerprint>', 'rule:<kind>:<rule id>', 'file:<path>' and the marker
-- 'scope:files', which asks for the finding's file to be listed as well.
-- NULL is a report stored before this column or a parser with no proof.
ALTER TABLE reports ADD COLUMN examined_keys TEXT[];

-- Whether a report proves it looked for one finding. Auto-fix and the report
-- delete both ask this, so the rule lives here once. A complete report vouches
-- for the kinds it covers; any report that is not partial vouches for a
-- finding its keys name.
CREATE FUNCTION report_examined_finding(
    completeness TEXT, kinds TEXT[], keys TEXT[],
    f_id UUID, f_kind TEXT, f_fingerprint TEXT
) RETURNS BOOLEAN LANGUAGE sql STABLE AS $$
    SELECT COALESCE(
        (completeness = 'complete' AND f_kind = ANY(kinds))
        OR (completeness <> 'partial' AND (
            ('fp:' || f_fingerprint) = ANY(keys)
            OR (
                EXISTS (
                    SELECT 1 FROM finding_dimensions d
                    WHERE d.finding_id = f_id AND d.dim_key = 'rule_id'
                      AND ('rule:' || f_kind || ':' || d.dim_value) = ANY(keys)
                )
                AND (
                    NOT ('scope:files' = ANY(keys))
                    OR EXISTS (
                        SELECT 1 FROM finding_dimensions d
                        WHERE d.finding_id = f_id AND d.dim_key = 'file'
                          AND ('file:' || d.dim_value) = ANY(keys)
                    )
                )
            )
        )),
        FALSE)
$$;
