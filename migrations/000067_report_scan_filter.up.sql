-- A scan can be told to report only part of what it finds: Trivy
-- --severity HIGH,CRITICAL or --ignore-unfixed, Grype --only-fixed. The tool
-- writes no trace of that into its output, so the uploader declares it and the
-- report stores it. NULL filter_severities means no severity filter. A report
-- vouches for the absence of a finding only when the finding is inside the
-- filter, so a filtered scan no longer closes the findings it hid by design.
ALTER TABLE reports
    ADD COLUMN filter_severities TEXT[],
    ADD COLUMN filter_fixable_only BOOLEAN NOT NULL DEFAULT false,
    ADD CONSTRAINT reports_filter_severities_check CHECK (
        filter_severities IS NULL OR (
            cardinality(filter_severities) > 0
            AND filter_severities <@ ARRAY['critical', 'high', 'medium', 'low', 'unknown']::text[]
        )
    );

-- The examined test now also asks whether the finding is inside the report's
-- filter. The severity is the one the finding has in the report's scan scope,
-- or the finding's current severity when the scope holds no row for it. The
-- fix filter needs a non-empty fixed_version dimension on the finding. Every
-- caller passes the report's own filter columns and scan_scope_hash.
DROP FUNCTION IF EXISTS report_examined_finding(TEXT, TEXT[], TEXT[], UUID, TEXT, TEXT);

CREATE FUNCTION report_examined_finding(
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
        AND (
            filter_severities IS NULL
            OR COALESCE(
                (SELECT s.severity FROM finding_scope_severities s
                 WHERE s.finding_id = f_id AND s.scope_hash = COALESCE(scan_scope_hash, '')),
                (SELECT f.current_severity FROM findings f WHERE f.id = f_id)
            ) = ANY(filter_severities)
        )
        AND (
            NOT filter_fixable_only
            OR EXISTS (
                SELECT 1 FROM finding_dimensions fv
                WHERE fv.finding_id = f_id AND fv.dim_key = 'fixed_version' AND fv.dim_value <> ''
            )
        ),
        FALSE)
$$;
