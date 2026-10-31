DROP FUNCTION IF EXISTS report_examined_finding(TEXT, TEXT[], TEXT[], TEXT[], BOOLEAN, TEXT, UUID, TEXT, TEXT);

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

ALTER TABLE reports
    DROP CONSTRAINT IF EXISTS reports_filter_severities_check,
    DROP COLUMN IF EXISTS filter_fixable_only,
    DROP COLUMN IF EXISTS filter_severities;
