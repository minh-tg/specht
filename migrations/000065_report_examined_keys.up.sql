-- Per-finding proof that a report looked for a finding, written by parsers
-- whose output lists what they checked (a SARIF rule and artifact list,
-- Checkov passed checks). Kind-wide coverage stays in covered_finding_kinds.
-- Keys are 'fp:<fingerprint>', and per SARIF run n 'run:<n>:rule:<kind>:<rule
-- id>' and 'run:<n>:file:<path>'. A rule proves a finding absent only with a
-- file key of the same run, so one run's rule never vouches for a file another
-- run scanned. NULL is a report stored before this column or a parser with no
-- proof.
ALTER TABLE reports ADD COLUMN examined_keys TEXT[];

-- Whether a report proves it looked for one finding. Auto-fix and the report
-- delete both ask this, so the rule lives here once. A complete report vouches
-- for the kinds it covers; any report that is not partial vouches for a
-- finding its keys name. The run number is the text up to the second colon,
-- which a colon in a rule id or path cannot move.
CREATE FUNCTION report_examined_finding(
    completeness TEXT, kinds TEXT[], keys TEXT[],
    f_id UUID, f_kind TEXT, f_fingerprint TEXT
) RETURNS BOOLEAN LANGUAGE sql STABLE AS $$
    SELECT COALESCE(
        (completeness = 'complete' AND f_kind = ANY(kinds))
        OR (completeness <> 'partial' AND (
            ('fp:' || f_fingerprint) = ANY(keys)
            OR EXISTS (
                SELECT 1
                FROM unnest(keys) AS k(key)
                JOIN finding_dimensions r
                  ON r.finding_id = f_id AND r.dim_key = 'rule_id'
                JOIN finding_dimensions fl
                  ON fl.finding_id = f_id AND fl.dim_key = 'file'
                WHERE k.key LIKE 'run:%'
                  AND k.key = 'run:' || split_part(k.key, ':', 2) || ':rule:' || f_kind || ':' || r.dim_value
                  AND ('run:' || split_part(k.key, ':', 2) || ':file:' || fl.dim_value) = ANY(keys)
            )
        )),
        FALSE)
$$;
