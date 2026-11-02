-- A severity filter hides what the scanner rates outside it, and the scanner's
-- rating can change between two scans. The filter test of 000067 read the
-- severity the finding last had in the scope, so a finding the vendor re-rated
-- below a HIGH,CRITICAL filter vanished from the next filtered report and was
-- closed as fixed although no scan had looked at it. The server never sees the
-- new rating, so a report filtered by severity cannot vouch for the absence of
-- any finding. A filter that keeps every severity filters nothing. The fixable
-- filter still applies per finding through its fixed_version dimension.
--
-- report_filter_admits_absence is the filter half of the examined test, shared
-- with the baseline lookup of the introduced-only gate.
CREATE FUNCTION report_filter_admits_absence(
    filter_severities TEXT[], filter_fixable_only BOOLEAN, f_id UUID
) RETURNS BOOLEAN LANGUAGE sql STABLE AS $$
    SELECT (
        filter_severities IS NULL
        OR filter_severities @> ARRAY['unknown', 'low', 'medium', 'high', 'critical']::text[]
    )
    AND (
        NOT COALESCE(filter_fixable_only, false)
        OR EXISTS (
            SELECT 1 FROM finding_dimensions fv
            WHERE fv.finding_id = f_id AND fv.dim_key = 'fixed_version' AND fv.dim_value <> ''
        )
    )
$$;

-- scan_scope_hash is kept so every caller's argument list stays valid.
CREATE OR REPLACE FUNCTION report_examined_finding(
    completeness TEXT, kinds TEXT[], keys TEXT[],
    filter_severities TEXT[], filter_fixable_only BOOLEAN, scan_scope_hash TEXT,
    f_id UUID, f_kind TEXT, f_fingerprint TEXT
) RETURNS BOOLEAN LANGUAGE sql STABLE AS $$
    SELECT COALESCE(
        (
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
            ))
        )
        AND report_filter_admits_absence(filter_severities, filter_fixable_only, f_id),
        FALSE)
$$;
