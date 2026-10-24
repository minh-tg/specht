-- Aliases were kept in occurrence metadata before they became gate and waiver
-- inputs. Backfill them as dimensions so existing scan findings can match a
-- CVE alias without an ingest. Rows written here use source 'backfill' so the
-- down migration removes only this migration's work.
INSERT INTO finding_dimensions (finding_id, dim_key, dim_value, source)
SELECT DISTINCT f.id, 'alias', a.value, 'backfill'
FROM findings f
JOIN finding_occurrences o ON o.finding_id = f.id
CROSS JOIN LATERAL jsonb_array_elements_text(
    CASE
        WHEN jsonb_typeof(o.metadata->'specht'->'aliases') = 'array'
        THEN o.metadata->'specht'->'aliases'
        ELSE '[]'::jsonb
    END
) AS a(value)
WHERE a.value <> ''
ON CONFLICT (finding_id, dim_key, dim_value) DO NOTHING;
