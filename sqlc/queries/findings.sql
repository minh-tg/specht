-- name: UpsertFinding :one
INSERT INTO findings (
    project_id, finding_kind, fingerprint,
    current_title, current_severity, current_severity_rank,
    current_score, state, triage_status,
    first_seen_at, last_seen_at
) VALUES (
    $1, $2, $3,
    $4, $5, $6,
    $7, $8, $9,
    $10, $11
) ON CONFLICT (project_id, finding_kind, fingerprint) DO UPDATE SET
    current_title = EXCLUDED.current_title,
    current_severity = EXCLUDED.current_severity,
    current_severity_rank = EXCLUDED.current_severity_rank,
    current_score = EXCLUDED.current_score,
    last_seen_at = EXCLUDED.last_seen_at,
    state = CASE
        WHEN findings.state = 'fixed' THEN 'reopened'
        ELSE findings.state
    END,
    updated_at = NOW()
RETURNING *;

-- name: CreateFindingIfAbsent :one
-- Watcher persist path: insert the finding only when absent. Returns
-- pgx.ErrNoRows when a row with the same (project_id, finding_kind,
-- fingerprint) already exists — the daemon's re-poll guard. Occurrences are
-- created only for genuinely new findings (a new fingerprint), never on
-- re-poll hits of an existing watcher finding. The UNIQUE(finding_id,
-- report_id) constraint does not dedupe NULL report_ids.
INSERT INTO findings (
    project_id, finding_kind, fingerprint,
    current_title, current_severity, current_severity_rank,
    current_score, state, triage_status,
    first_seen_at, last_seen_at
) VALUES (
    $1, $2, $3,
    $4, $5, $6,
    $7, 'open', 'untriaged',
    NOW(), NOW()
)
ON CONFLICT (project_id, finding_kind, fingerprint) DO NOTHING
RETURNING *;

-- name: CreateOccurrence :one
INSERT INTO finding_occurrences (
    finding_id, report_id, title, description,
    severity, severity_rank, score,
    tool_name, tool_version, parser_version,
    location_summary, subject_summary, remediation,
    display, metadata, observed_at
) VALUES (
    $1, $2, $3, $4,
    $5, $6, $7,
    $8, $9, $10,
    $11, $12, $13,
    $14, $15, $16
) ON CONFLICT (finding_id, report_id) DO UPDATE SET observed_at = NOW()
RETURNING *;

-- name: ListFindingsByProject :many
SELECT f.* FROM findings f
WHERE f.project_id = $1
  AND (array_length($2::text[], 1) IS NULL OR f.current_severity = ANY($2))
  AND (array_length($3::text[], 1) IS NULL OR f.state = ANY($3))
  AND (array_length($4::text[], 1) IS NULL OR f.finding_kind = ANY($4))
  AND (array_length($5::text[], 1) IS NULL OR EXISTS (
    SELECT 1 FROM finding_occurrences fo
    JOIN reports r ON fo.report_id = r.id
    JOIN environments e ON r.environment_id = e.id
    WHERE fo.finding_id = f.id AND e.name = ANY($5)))
  AND (array_length($6::text[], 1) IS NULL OR EXISTS (
    SELECT 1 FROM finding_occurrences fo
    JOIN reports r ON fo.report_id = r.id
    JOIN targets t ON r.target_id = t.id
    WHERE fo.finding_id = f.id AND t.name = ANY($6)))
ORDER BY f.current_severity_rank DESC, f.created_at DESC
LIMIT $7 OFFSET $8;

-- name: GetFindingByID :one
SELECT * FROM findings WHERE id = $1;

-- name: GetFindingByFingerprint :one
SELECT * FROM findings
WHERE project_id = $1 AND finding_kind = $2 AND fingerprint = $3
FOR UPDATE;

-- name: ListFindingsByIDs :many
SELECT * FROM findings WHERE id = ANY($1::uuid[]);

-- name: UpdateFindingAnalysis :one
UPDATE findings SET
    analysis_state = $2,
    gate_effect = $3,
    analysis_expires_at = $4,
    analysis_reason = $5,
    analysis_source = $6,
    manual_override = $7,
    review_required = $8,
    analysis_updated_at = NOW(),
    analysis_updated_by = $9,
    updated_at = NOW()
WHERE id = $1
RETURNING *;

-- name: BulkUpdateFindingAnalysis :many
UPDATE findings SET
    analysis_state = $2,
    gate_effect = $3,
    analysis_expires_at = $4,
    analysis_reason = $5,
    analysis_source = $6,
    manual_override = $7,
    review_required = $8,
    analysis_updated_at = NOW(),
    analysis_updated_by = $9,
    updated_at = NOW()
WHERE id = ANY($1::uuid[])
RETURNING *;

-- name: CreateFindingEvent :one
INSERT INTO finding_events (
    finding_id, user_id, event_type, old_value, new_value, comment, changes
) VALUES (
    $1, $2, $3, $4, $5, $6, $7
) RETURNING *;

-- name: ListFindingEvents :many
SELECT * FROM finding_events
WHERE finding_id = $1
  AND (array_length($2::text[], 1) IS NULL OR event_type = ANY($2))
ORDER BY created_at DESC
LIMIT $3 OFFSET $4;

-- name: ListGateCandidates :many
-- Batch gate-candidate loader: one round trip returns every finding that may
-- block a project's gate together with its environment/target/artifact
-- context and latest reachability assessment. The query is a performance
-- prefilter only — gate.Gate.Evaluate is the authoritative policy. Context
-- comes from the most recent occurrence's report; NULL report_id (watcher
-- findings) has no context and joins as NULL.
SELECT
    f.id,
    f.project_id,
    f.finding_kind,
    f.fingerprint,
    f.current_title,
    f.current_severity_rank,
    f.analysis_state,
    f.introduced_by_report_id,
    f.introduced_commit_sha,
    COALESCE(ra.state, 'unknown'::reachability_state) AS reachability_state,
    ctx.environment_id,
    ctx.target_id,
    ctx.artifact_id
FROM findings f
LEFT JOIN LATERAL (
    SELECT r.environment_id, r.target_id, r.artifact_id
    FROM finding_occurrences fo
    JOIN reports r ON fo.report_id = r.id
    WHERE fo.finding_id = f.id
    ORDER BY fo.observed_at DESC
    LIMIT 1
) ctx ON true
LEFT JOIN LATERAL (
    SELECT ra.state
    FROM reachability_assessments ra
    WHERE ra.finding_id = f.id
    ORDER BY ra.updated_at DESC
    LIMIT 1
) ra ON true
WHERE f.project_id = $1
  AND f.current_severity_rank >= $2
  AND f.gate_effect = 'block'
  AND f.state IN ('open', 'reopened')
ORDER BY f.current_severity_rank DESC, f.created_at DESC;

-- name: GetFindingContext :one
SELECT r.environment_id, r.target_id, r.artifact_id
FROM finding_occurrences fo
JOIN reports r ON fo.report_id = r.id
WHERE fo.finding_id = $1
ORDER BY fo.observed_at DESC
LIMIT 1;
-- name: GetFindingDisplayContext :one
SELECT t.name AS target_name, t.kind AS target_kind, t.owner AS target_owner,
    e.name AS environment_name, r.branch AS branch, r.commit_sha AS commit_sha,
    fo.tool_name AS tool_name, fo.location_summary AS location_summary,
    fo.metadata AS metadata
FROM finding_occurrences fo
JOIN reports r ON fo.report_id = r.id
LEFT JOIN targets t ON r.target_id = t.id
LEFT JOIN environments e ON r.environment_id = e.id
WHERE fo.finding_id = $1
ORDER BY fo.observed_at DESC
LIMIT 1;



-- name: HasDimension :one
SELECT EXISTS (
    SELECT 1 FROM finding_dimensions
    WHERE finding_id = $1 AND dim_key = $2 AND dim_value != ''
) AS exists;
-- name: ListFindingDimensions :many
SELECT dim_key, dim_value, source
FROM finding_dimensions
WHERE finding_id = $1
ORDER BY dim_key, dim_value;
-- name: OccurrenceExists :one
SELECT EXISTS (
    SELECT 1 FROM finding_occurrences
    WHERE finding_id = $1 AND report_id = $2
) AS exists;

-- name: MarkFindingFixed :one
UPDATE findings SET state = 'fixed', updated_at = NOW()
WHERE id = $1
RETURNING *;

-- name: SetFindingIntroducedBy :one
-- Materializes introduced-by-change attribution (SOLO-184): the report that
-- first observed the finding and the revision it scanned. Set once at
-- creation; refreshed only through this query when improved correlation
-- evidence arrives, so history stays revisable without silent rewrites.
UPDATE findings SET
    introduced_by_report_id = $2,
    introduced_commit_sha = $3,
    updated_at = NOW()
WHERE id = $1
RETURNING *;

-- name: ListFindingsIntroducedByReport :many
-- Findings a single report introduced, for introduced-only gate views and
-- change-scoped triage. Pre-existing findings observed (but not introduced)
-- by the report are excluded by construction.
SELECT * FROM findings
WHERE project_id = $1 AND introduced_by_report_id = $2
ORDER BY current_severity_rank DESC, created_at DESC;

-- name: UpsertDimension :one
INSERT INTO finding_dimensions (
    finding_id, dim_key, dim_value, source
) VALUES (
    $1, $2, $3, $4
) ON CONFLICT (finding_id, dim_key, dim_value) DO UPDATE SET
    source = EXCLUDED.source
RETURNING *;

-- name: FindScaFindingIdForPurlAndCve :one
-- Gap-fill check for the CVE feed watcher: returns the id of a scan-derived
-- SCA finding that already covers the (purl, vulnerability) pair in the
-- project, or pgx.ErrNoRows when none does. The watcher must NOT create a
-- cve_watcher finding when this returns a row (design: never reopen, never
-- duplicate), and it attaches the auto_rule_skipped event to the returned
-- finding. The decision conveys the skip but not the suppressing id, so
-- the wiring re-uses this query to resolve it.
--
-- Matching rules (gap-fill join keys):
--   * purl dimension matches at NAME-LEVEL: the stored dimension value is
--     truncated at the LAST '@' version separator, aligned with the Go
--     purlNameLevel helper (findings.go), so version-less osv-scanner purls
--     still dedupe against versioned watcher candidates. A non-purl fallback
--     containing '@' in its name (e.g. "corp@vendor/pkg@1.0.0") resolves to
--     "corp@vendor/pkg" — the same name-level identity Go computes. Values
--     with no '@' compare verbatim;
--   * vulnerability_id dimension matches ANY candidate id (primary CVE id
--     plus aliases — GHSA-only advisories still dedupe against existing
--     GHSA- or OSV-id findings, never exact-CVE-string only);
--   * findings in ANY state (open or fixed) suppress the watcher — there is
--     no reopen logic.
SELECT f.id
FROM findings f
JOIN finding_dimensions dp
  ON dp.finding_id = f.id
 AND dp.dim_key = 'purl'
 AND dp.dim_value != ''
JOIN finding_dimensions dv
  ON dv.finding_id = f.id
 AND dv.dim_key = 'vulnerability_id'
 AND dv.dim_value != ''
WHERE f.project_id = sqlc.arg(project_id)
  AND f.finding_kind = 'sca'
  AND COALESCE(substring(dp.dim_value from '^(.*)@'), dp.dim_value) = sqlc.arg(purl_name)
  AND dv.dim_value = ANY(sqlc.arg(candidate_ids)::text[])
LIMIT 1;

-- name: ListFindingsByFingerprints :many
SELECT * FROM findings
WHERE project_id = $1
  AND finding_kind = $2
  AND fingerprint = ANY($3::text[]);

-- name: ListFindingIDsPresentInReport :many
SELECT finding_id FROM finding_occurrences
WHERE report_id = $1
  AND finding_id = ANY($2::uuid[]);

-- name: BulkUpsertFindings :many
WITH input_rows AS (
    SELECT
        $1::uuid AS project_id,
        k.val::text AS finding_kind,
        f.val::text AS fingerprint,
        t.val::text AS title,
        s.val::text AS severity,
        sr.val::smallint AS severity_rank,
        sc.val::numeric AS score,
        $2::timestamptz AS observed_at
    FROM unnest($3::text[]) WITH ORDINALITY AS k(val, ord)
    JOIN unnest($4::text[]) WITH ORDINALITY AS f(val, ord) ON k.ord = f.ord
    JOIN unnest($5::text[]) WITH ORDINALITY AS t(val, ord) ON k.ord = t.ord
    JOIN unnest($6::text[]) WITH ORDINALITY AS s(val, ord) ON k.ord = s.ord
    JOIN unnest($7::smallint[]) WITH ORDINALITY AS sr(val, ord) ON k.ord = sr.ord
    JOIN unnest($8::numeric[]) WITH ORDINALITY AS sc(val, ord) ON k.ord = sc.ord
    ORDER BY k.val, f.val
)
INSERT INTO findings (
    project_id, finding_kind, fingerprint,
    current_title, current_severity, current_severity_rank,
    current_score, state, triage_status,
    first_seen_at, last_seen_at
)
SELECT
    ir.project_id, ir.finding_kind, ir.fingerprint,
    ir.title, ir.severity, ir.severity_rank,
    ir.score, 'open', 'untriaged',
    ir.observed_at, ir.observed_at
FROM input_rows ir
ON CONFLICT (project_id, finding_kind, fingerprint) DO UPDATE SET
    current_title = EXCLUDED.current_title,
    current_severity = EXCLUDED.current_severity,
    current_severity_rank = EXCLUDED.current_severity_rank,
    current_score = EXCLUDED.current_score,
    last_seen_at = GREATEST(findings.last_seen_at, EXCLUDED.last_seen_at),
    state = CASE
        WHEN findings.state = 'fixed' THEN 'reopened'
        ELSE findings.state
    END,
    updated_at = NOW()
RETURNING id, fingerprint, (xmax = 0) AS is_inserted, state;

-- name: BulkInsertOccurrences :exec
INSERT INTO finding_occurrences (
    finding_id, report_id, title, description,
    severity, severity_rank, score,
    tool_name, tool_version, parser_version,
    location_summary, subject_summary, remediation,
    display, metadata, observed_at
)
SELECT
    f.val::uuid, $1::uuid, t.val::text, d.val::text,
    s.val::text, sr.val::smallint, sc.val::numeric,
    $2::text, $3::text, $4::text,
    loc.val::text, sub.val::text, rem.val::text,
    disp.val::jsonb, meta.val::jsonb, $5::timestamptz
FROM unnest($6::uuid[]) WITH ORDINALITY AS f(val, ord)
JOIN unnest($7::text[]) WITH ORDINALITY AS t(val, ord) ON f.ord = t.ord
JOIN unnest($8::text[]) WITH ORDINALITY AS d(val, ord) ON f.ord = d.ord
JOIN unnest($9::text[]) WITH ORDINALITY AS s(val, ord) ON f.ord = s.ord
JOIN unnest($10::smallint[]) WITH ORDINALITY AS sr(val, ord) ON f.ord = sr.ord
JOIN unnest($11::numeric[]) WITH ORDINALITY AS sc(val, ord) ON f.ord = sc.ord
JOIN unnest($12::text[]) WITH ORDINALITY AS loc(val, ord) ON f.ord = loc.ord
JOIN unnest($13::text[]) WITH ORDINALITY AS sub(val, ord) ON f.ord = sub.ord
JOIN unnest($14::text[]) WITH ORDINALITY AS rem(val, ord) ON f.ord = rem.ord
JOIN unnest($15::jsonb[]) WITH ORDINALITY AS disp(val, ord) ON f.ord = disp.ord
JOIN unnest($16::jsonb[]) WITH ORDINALITY AS meta(val, ord) ON f.ord = meta.ord
ON CONFLICT (finding_id, report_id) DO UPDATE SET observed_at = NOW();

-- name: BulkUpsertDimensions :exec
INSERT INTO finding_dimensions (
    finding_id, dim_key, dim_value, source
)
SELECT
    f.val::uuid, k.val::text, v.val::text, $1::text
FROM unnest($2::uuid[]) WITH ORDINALITY AS f(val, ord)
JOIN unnest($3::text[]) WITH ORDINALITY AS k(val, ord) ON f.ord = k.ord
JOIN unnest($4::text[]) WITH ORDINALITY AS v(val, ord) ON f.ord = v.ord
ON CONFLICT (finding_id, dim_key, dim_value) DO UPDATE SET
    source = EXCLUDED.source;

-- name: RecordReportIntroducedFindings :exec
INSERT INTO report_introduced_findings (
    report_id, finding_id, baseline_report_id, change_type
)
SELECT
    $1::uuid, f.val::uuid, $2, ct.val::text
FROM unnest($3::uuid[]) WITH ORDINALITY AS f(val, ord)
JOIN unnest($4::text[]) WITH ORDINALITY AS ct(val, ord) ON f.ord = ct.ord
ON CONFLICT (report_id, finding_id) DO UPDATE SET
    change_type = EXCLUDED.change_type;

-- name: ListIntroducedGateCandidates :many
SELECT
    f.id,
    f.project_id,
    f.finding_kind,
    f.fingerprint,
    f.current_title,
    f.current_severity_rank,
    f.analysis_state,
    f.introduced_by_report_id,
    f.introduced_commit_sha,
    COALESCE(ra.state, 'unknown'::reachability_state) AS reachability_state,
    ctx.environment_id,
    ctx.target_id,
    ctx.artifact_id,
    rif.change_type
FROM report_introduced_findings rif
JOIN findings f ON rif.finding_id = f.id
LEFT JOIN LATERAL (
    SELECT r.environment_id, r.target_id, r.artifact_id
    FROM finding_occurrences fo
    JOIN reports r ON fo.report_id = r.id
    WHERE fo.finding_id = f.id
    ORDER BY fo.observed_at DESC
    LIMIT 1
) ctx ON true
LEFT JOIN LATERAL (
    SELECT ra.state
    FROM reachability_assessments ra
    WHERE ra.finding_id = f.id
    ORDER BY ra.updated_at DESC
    LIMIT 1
) ra ON true
WHERE rif.report_id = $1
  AND f.current_severity_rank >= $2
  AND f.gate_effect = 'block'
  AND f.state IN ('open', 'reopened')
ORDER BY f.current_severity_rank DESC, f.created_at DESC;

-- name: ListFindingsIntroducedByCommit :many
SELECT * FROM findings
WHERE project_id = $1
  AND introduced_commit_sha = $2
ORDER BY current_severity_rank DESC, created_at DESC;
