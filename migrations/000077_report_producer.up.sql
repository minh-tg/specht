-- A generic SARIF upload is stored under the scanner name "sarif", so the
-- report list showed "sarif" for Gosec, CodeQL or Hadolint. producer_name keeps
-- the tool names the file itself gives (runs[].tool.driver.name). It is display
-- only: scope, closing and verification keep using tool_name.
ALTER TABLE reports ADD COLUMN producer_name TEXT;

-- Reports whose raw payload is still kept get the name back. Expired payloads
-- hold JSON null and stay NULL.
UPDATE reports r
SET producer_name = left(names.joined, 255)
FROM (
    SELECT rep.id, string_agg(DISTINCT run->'tool'->'driver'->>'name', ', ') AS joined
    FROM reports rep
    CROSS JOIN LATERAL jsonb_array_elements(rep.raw_data->'runs') AS run
    WHERE rep.tool_name = 'sarif'
      AND jsonb_typeof(rep.raw_data->'runs') = 'array'
      AND jsonb_typeof(run) = 'object'
      AND COALESCE(run->'tool'->'driver'->>'name', '') <> ''
    GROUP BY rep.id
) names
WHERE r.id = names.id;
