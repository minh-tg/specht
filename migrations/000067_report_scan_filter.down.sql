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

-- The declared scan filters are kept so that applying 000067 again restores
-- them. Without the copy a Trivy --severity HIGH,CRITICAL report would come
-- back with no filter and claim to have examined every severity. The up
-- migration restores from this table and drops it.
DROP TABLE IF EXISTS migration_000067_report_filters;
CREATE TABLE migration_000067_report_filters AS
SELECT id, filter_severities, filter_fixable_only
FROM reports
WHERE filter_severities IS NOT NULL OR filter_fixable_only;

ALTER TABLE reports
    DROP CONSTRAINT IF EXISTS reports_filter_severities_check,
    DROP COLUMN IF EXISTS filter_fixable_only,
    DROP COLUMN IF EXISTS filter_severities;
