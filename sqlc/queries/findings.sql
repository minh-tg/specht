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
        WHEN findings.state = 'archived' THEN 'open'
        ELSE findings.state
    END,
    updated_at = NOW()
RETURNING *;

-- name: RefreshFindingScopeSeverity :one
-- The caller holds the finding row lock before changing its scope rows.
UPDATE findings f
SET current_severity = highest.severity,
    current_severity_rank = highest.severity_rank
FROM (
    SELECT severity, severity_rank
    FROM finding_scope_severities
    WHERE finding_id = $1
    ORDER BY severity_rank DESC, scope_hash
    LIMIT 1
) highest
WHERE f.id = $1
RETURNING f.*;

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
-- search is a LIKE pattern the caller has escaped; sort_key and sort_dir are
-- validated by the caller and fall back to the severity order below.
SELECT f.* FROM findings f
WHERE f.project_id = $1
  AND (array_length($2::text[], 1) IS NULL OR f.current_severity = ANY($2))
  AND (CASE WHEN array_length($3::text[], 1) IS NULL THEN f.state <> 'archived' ELSE f.state = ANY($3) END)
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
  AND (array_length(sqlc.arg(analysis_states)::text[], 1) IS NULL
    OR COALESCE(NULLIF(f.analysis_state, ''), 'unanalyzed') = ANY(sqlc.arg(analysis_states)::text[]))
  AND (sqlc.arg(search)::text = ''
    OR f.current_title ILIKE '%' || sqlc.arg(search)::text || '%'
    OR f.fingerprint ILIKE '%' || sqlc.arg(search)::text || '%')
ORDER BY
  CASE WHEN sqlc.arg(sort_key)::text = 'severity' AND sqlc.arg(sort_dir)::text = 'desc' THEN f.current_severity_rank END DESC,
  CASE WHEN sqlc.arg(sort_key)::text = 'severity' AND sqlc.arg(sort_dir)::text = 'asc' THEN f.current_severity_rank END ASC,
  CASE WHEN sqlc.arg(sort_key)::text = 'first_seen' AND sqlc.arg(sort_dir)::text = 'desc' THEN f.first_seen_at END DESC,
  CASE WHEN sqlc.arg(sort_key)::text = 'first_seen' AND sqlc.arg(sort_dir)::text = 'asc' THEN f.first_seen_at END ASC,
  CASE WHEN sqlc.arg(sort_key)::text = 'last_seen' AND sqlc.arg(sort_dir)::text = 'desc' THEN f.last_seen_at END DESC,
  CASE WHEN sqlc.arg(sort_key)::text = 'last_seen' AND sqlc.arg(sort_dir)::text = 'asc' THEN f.last_seen_at END ASC,
  CASE WHEN sqlc.arg(sort_key)::text = 'title' AND sqlc.arg(sort_dir)::text = 'desc' THEN lower(f.current_title) END DESC,
  CASE WHEN sqlc.arg(sort_key)::text = 'title' AND sqlc.arg(sort_dir)::text = 'asc' THEN lower(f.current_title) END ASC,
  f.current_severity_rank DESC, f.created_at DESC, f.id DESC
LIMIT $7 OFFSET $8;

-- name: CountFindingsByProject :one
-- The same filter predicates as ListFindingsByProject, without the page
-- window. Served as X-Total-Count so a client can render "n of m" without
-- paging to the end; keeps the list query's plan and row shape untouched.
SELECT COUNT(*) FROM findings f
WHERE f.project_id = $1
  AND (array_length($2::text[], 1) IS NULL OR f.current_severity = ANY($2))
  AND (CASE WHEN array_length($3::text[], 1) IS NULL THEN f.state <> 'archived' ELSE f.state = ANY($3) END)
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
  AND (array_length(sqlc.arg(analysis_states)::text[], 1) IS NULL
    OR COALESCE(NULLIF(f.analysis_state, ''), 'unanalyzed') = ANY(sqlc.arg(analysis_states)::text[]))
  AND (sqlc.arg(search)::text = ''
    OR f.current_title ILIKE '%' || sqlc.arg(search)::text || '%'
    OR f.fingerprint ILIKE '%' || sqlc.arg(search)::text || '%');

-- name: GetFindingByID :one
SELECT * FROM findings WHERE id = $1;

-- name: GetFindingByFingerprint :one
SELECT * FROM findings
WHERE project_id = $1 AND finding_kind = $2 AND fingerprint = $3
FOR UPDATE;

-- name: ListFindingsByIDs :many
SELECT * FROM findings WHERE id = ANY($1::uuid[]);

-- name: UpdateFindingAnalysis :one
-- expected_state is an optional precondition: when set, the row is updated
-- only while analysis_state still equals it, so a caller that read the
-- finding first cannot overwrite a change made in between.
UPDATE findings SET
    analysis_state = sqlc.arg(analysis_state),
    gate_effect = sqlc.arg(gate_effect),
    analysis_expires_at = sqlc.arg(analysis_expires_at),
    analysis_reason = sqlc.arg(analysis_reason),
    analysis_source = sqlc.arg(analysis_source),
    manual_override = sqlc.arg(manual_override),
    review_required = sqlc.arg(review_required),
    analysis_updated_at = NOW(),
    analysis_updated_by = sqlc.arg(analysis_updated_by),
    updated_at = NOW()
WHERE id = sqlc.arg(id)
  AND (sqlc.narg(expected_state)::text IS NULL OR analysis_state = sqlc.narg(expected_state)::text)
RETURNING *;

-- name: LockFindingForUpdate :one
SELECT * FROM findings WHERE id = $1 FOR UPDATE;

-- name: GetNewestAnalysisEvent :one
-- The finding's newest event of any type that can change or flag its
-- analysis. Triage undo is only allowed against this event.
SELECT * FROM finding_events
WHERE finding_id = $1
  AND event_type IN (
      'analysis_changed', 'bulk_triage_applied',
      'reopened_severity_change', 'reopened_fix_available'
  )
ORDER BY created_at DESC, id DESC
LIMIT 1;

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

-- name: BulkCreateFindingEvents :exec
INSERT INTO finding_events (
    finding_id, user_id, event_type, old_value, new_value, comment, changes
)
SELECT
    f_id, $2, $3, $4, $5, $6, $7
FROM UNNEST($1::uuid[]) AS f_id;

-- name: ListFindingEvents :many
SELECT * FROM finding_events
WHERE finding_id = $1
  AND (array_length($2::text[], 1) IS NULL OR event_type = ANY($2))
ORDER BY created_at DESC, id DESC
LIMIT $3 OFFSET $4;

-- name: ListGateCandidates :many
-- Batch gate-candidate loader: one round trip returns every finding that may
-- block a project's gate together with its environment/target/artifact
-- context and latest reachability assessment. The query is a performance
-- prefilter only — gate.Gate.Evaluate is the authoritative policy. Context
-- comes from the most recent occurrence's report; NULL report_id (watcher
-- findings) has no context and joins as NULL. The three observed_* arrays are
-- aligned: entry i is the (environment, target, artifact) of one distinct
-- context whose reports observed the finding, '' for a column the report left
-- empty. A context-scoped waiver is checked against every one of them, not
-- only the newest scan.
SELECT
    f.id,
    f.project_id,
    f.finding_kind,
    f.fingerprint,
    f.current_title,
    f.current_severity_rank,
    (CASE WHEN f.analysis_expires_at <= NOW() THEN 'unanalyzed' ELSE f.analysis_state END)::text AS analysis_state,
    f.introduced_by_report_id,
    f.introduced_commit_sha,
    COALESCE(ra.state, 'unknown'::reachability_state) AS reachability_state,
    ctx.environment_id,
    ctx.target_id,
    ctx.artifact_id,
    COALESCE(obs.environment_ids, '{}')::text[] AS observed_environment_ids,
    COALESCE(obs.target_ids, '{}')::text[] AS observed_target_ids,
    COALESCE(obs.artifact_ids, '{}')::text[] AS observed_artifact_ids,
    ARRAY(SELECT DISTINCT d.dim_value FROM finding_dimensions d
          WHERE d.finding_id = f.id AND d.dim_key = 'alias'
          ORDER BY d.dim_value)::text[] AS aliases
FROM open_findings f
LEFT JOIN LATERAL (
    SELECT r.environment_id, r.target_id, r.artifact_id
    FROM finding_occurrences fo
    JOIN reports r ON fo.report_id = r.id
    WHERE fo.finding_id = f.id
    ORDER BY fo.observed_at DESC, fo.id DESC
    LIMIT 1
) ctx ON true
LEFT JOIN LATERAL (
    SELECT
        array_agg(o.environment_id ORDER BY o.environment_id, o.target_id, o.artifact_id) AS environment_ids,
        array_agg(o.target_id ORDER BY o.environment_id, o.target_id, o.artifact_id) AS target_ids,
        array_agg(o.artifact_id ORDER BY o.environment_id, o.target_id, o.artifact_id) AS artifact_ids
    FROM (
        SELECT DISTINCT
            COALESCE(er.environment_id::text, '') AS environment_id,
            COALESCE(er.target_id::text, '') AS target_id,
            COALESCE(er.artifact_id::text, '') AS artifact_id
        FROM finding_occurrences eo
        JOIN reports er ON eo.report_id = er.id
        WHERE eo.finding_id = f.id
    ) o
) obs ON true
LEFT JOIN LATERAL (
    SELECT ra.state
    FROM reachability_assessments ra
    WHERE ra.finding_id = f.id
    ORDER BY ra.updated_at DESC, ra.id DESC
    LIMIT 1
) ra ON true
WHERE f.project_id = $1
  AND f.current_severity_rank >= $2
  AND (f.gate_effect = 'block' OR f.analysis_expires_at <= NOW())
ORDER BY f.current_severity_rank DESC, f.created_at DESC, f.id DESC;

-- name: ListFindingObservedContexts :many
-- Every distinct (environment, target, artifact) whose reports observed the
-- finding; '' stands for a column the report left empty. The per-finding
-- counterpart of the observed_* arrays in ListGateCandidates.
SELECT DISTINCT
    COALESCE(r.environment_id::text, '')::text AS environment_id,
    COALESCE(r.target_id::text, '')::text AS target_id,
    COALESCE(r.artifact_id::text, '')::text AS artifact_id
FROM finding_occurrences fo
JOIN reports r ON fo.report_id = r.id
WHERE fo.finding_id = $1
ORDER BY 1, 2, 3;

-- name: GetFindingContext :one
SELECT r.environment_id, r.target_id, r.artifact_id
FROM finding_occurrences fo
JOIN reports r ON fo.report_id = r.id
WHERE fo.finding_id = $1
ORDER BY fo.observed_at DESC, fo.id DESC
LIMIT 1;
-- name: GetFindingDisplayContext :one
SELECT t.name AS target_name, t.kind AS target_kind, t.owner AS target_owner,
    e.name AS environment_name, r.branch AS branch, r.commit_sha AS commit_sha,
    fo.tool_name AS tool_name, fo.location_summary AS location_summary,
    fo.metadata AS metadata,
    CAST((r.raw_data = 'null'::jsonb) IS TRUE AS boolean) AS raw_data_expired,
    r.created_at AS report_created_at
FROM finding_occurrences fo
JOIN reports r ON fo.report_id = r.id
LEFT JOIN targets t ON r.target_id = t.id
LEFT JOIN environments e ON r.environment_id = e.id
WHERE fo.finding_id = $1
ORDER BY fo.observed_at DESC, fo.id DESC
LIMIT 1;

-- name: ListFindingDisplayContextsByIDs :many
SELECT DISTINCT ON (fo.finding_id)
    fo.finding_id,
    t.name AS target_name, t.kind AS target_kind, t.owner AS target_owner,
    e.name AS environment_name, r.branch AS branch, r.commit_sha AS commit_sha,
    fo.tool_name AS tool_name, fo.location_summary AS location_summary,
    fo.metadata AS metadata
FROM finding_occurrences fo
JOIN reports r ON fo.report_id = r.id
LEFT JOIN targets t ON r.target_id = t.id
LEFT JOIN environments e ON r.environment_id = e.id
WHERE fo.finding_id = ANY($1::uuid[])
ORDER BY fo.finding_id, fo.observed_at DESC, fo.id DESC;



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
-- Materializes introduced-by-change attribution: the report that
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
ORDER BY current_severity_rank DESC, created_at DESC, id DESC;

-- name: ReassignFindingIntroducedBy :exec
-- Duplicate-race cleanup: re-points findings that a losing processing report
-- introduced at the report that won the race, so deleting the loser does not
-- null their attribution. Findings the winner introduced itself are left
-- alone because their report id is not the loser's.
UPDATE findings SET
    introduced_by_report_id = $3,
    updated_at = NOW()
WHERE project_id = $1 AND introduced_by_report_id = $2;

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
--     truncated at the last '@' after the final namespace separator,
--     aligned with the Go purlNameLevel helper, so version-less osv-scanner purls
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
  AND CASE WHEN starts_with(dp.dim_value, 'pkg:')
        THEN regexp_replace(dp.dim_value, '@[^/]*$', '')
        ELSE COALESCE(substring(dp.dim_value from '^(.*)@'), dp.dim_value)
      END = sqlc.arg(purl_name)
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
        WHEN findings.state = 'archived' THEN 'open'
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
    occurrence.finding_id, occurrence.report_id, occurrence.title, occurrence.description,
    occurrence.severity, occurrence.severity_rank, occurrence.score,
    occurrence.tool_name, occurrence.tool_version, occurrence.parser_version,
    occurrence.location_summary, occurrence.subject_summary, occurrence.remediation,
    occurrence.display, occurrence.metadata, NOW()
FROM jsonb_to_recordset(sqlc.arg(occurrences)::jsonb) AS occurrence(
    finding_id uuid,
    report_id uuid,
    title text,
    description text,
    severity text,
    severity_rank smallint,
    score numeric,
    tool_name text,
    tool_version text,
    parser_version text,
    location_summary text,
    subject_summary text,
    remediation text,
    display jsonb,
    metadata jsonb
)
ON CONFLICT (finding_id, report_id) DO UPDATE SET observed_at = NOW();

-- name: BulkUpsertDimensions :exec
WITH input_rows AS (
    SELECT DISTINCT f.val::uuid AS finding_id, k.val::text AS dim_key, v.val::text AS dim_value
    FROM unnest(sqlc.arg(finding_ids)::uuid[]) WITH ORDINALITY AS f(val, ord)
    JOIN unnest(sqlc.arg(dim_keys)::text[]) WITH ORDINALITY AS k(val, ord) ON f.ord = k.ord
    JOIN unnest(sqlc.arg(dim_values)::text[]) WITH ORDINALITY AS v(val, ord) ON f.ord = v.ord
)
INSERT INTO finding_dimensions (
    finding_id, dim_key, dim_value, source
)
SELECT finding_id, dim_key, dim_value, sqlc.arg(source)::text
FROM input_rows
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

-- name: ListReportIntroducedChangeTypes :many
-- The change type one report recorded for each of the given findings it
-- introduced. Findings the report did not introduce return no row.
SELECT finding_id, change_type
FROM report_introduced_findings
WHERE report_id = $1
  AND finding_id = ANY(sqlc.arg(finding_ids)::uuid[]);

-- name: ListIntroducedGateCandidates :many
SELECT
    f.id,
    f.project_id,
    f.finding_kind,
    f.fingerprint,
    f.current_title,
    f.current_severity_rank,
    (CASE WHEN f.analysis_expires_at <= NOW() THEN 'unanalyzed' ELSE f.analysis_state END)::text AS analysis_state,
    f.introduced_by_report_id,
    f.introduced_commit_sha,
    COALESCE(ra.state, 'unknown'::reachability_state) AS reachability_state,
    ctx.environment_id,
    ctx.target_id,
    ctx.artifact_id,
    COALESCE(obs.environment_ids, '{}')::text[] AS observed_environment_ids,
    COALESCE(obs.target_ids, '{}')::text[] AS observed_target_ids,
    COALESCE(obs.artifact_ids, '{}')::text[] AS observed_artifact_ids,
    ARRAY(SELECT DISTINCT d.dim_value FROM finding_dimensions d
          WHERE d.finding_id = f.id AND d.dim_key = 'alias'
          ORDER BY d.dim_value)::text[] AS aliases,
    rif.change_type
FROM report_introduced_findings rif
JOIN open_findings f ON rif.finding_id = f.id
LEFT JOIN LATERAL (
    SELECT r.environment_id, r.target_id, r.artifact_id
    FROM finding_occurrences fo
    JOIN reports r ON fo.report_id = r.id
    WHERE fo.finding_id = f.id
    ORDER BY fo.observed_at DESC, fo.id DESC
    LIMIT 1
) ctx ON true
LEFT JOIN LATERAL (
    SELECT
        array_agg(o.environment_id ORDER BY o.environment_id, o.target_id, o.artifact_id) AS environment_ids,
        array_agg(o.target_id ORDER BY o.environment_id, o.target_id, o.artifact_id) AS target_ids,
        array_agg(o.artifact_id ORDER BY o.environment_id, o.target_id, o.artifact_id) AS artifact_ids
    FROM (
        SELECT DISTINCT
            COALESCE(er.environment_id::text, '') AS environment_id,
            COALESCE(er.target_id::text, '') AS target_id,
            COALESCE(er.artifact_id::text, '') AS artifact_id
        FROM finding_occurrences eo
        JOIN reports er ON eo.report_id = er.id
        WHERE eo.finding_id = f.id
    ) o
) obs ON true
LEFT JOIN LATERAL (
    SELECT ra.state
    FROM reachability_assessments ra
    WHERE ra.finding_id = f.id
    ORDER BY ra.updated_at DESC, ra.id DESC
    LIMIT 1
) ra ON true
WHERE rif.report_id = $1
  AND f.current_severity_rank >= $2
  AND f.project_id = $3
  AND (f.gate_effect = 'block' OR f.analysis_expires_at <= NOW())
ORDER BY f.current_severity_rank DESC, f.created_at DESC, f.id DESC;

-- name: ListFindingsIntroducedByCommit :many
SELECT f.* FROM findings f
WHERE f.project_id = $1
  AND f.state <> 'archived'
  AND EXISTS (
      SELECT 1
      FROM report_introduced_findings rif
      JOIN reports r ON r.id = rif.report_id
      WHERE rif.finding_id = f.id
        AND r.project_id = $1
        AND r.commit_sha = sqlc.narg(commit_sha)
        AND r.status = 'completed'
  )
ORDER BY f.current_severity_rank DESC, f.created_at DESC, f.id DESC;

-- name: LockAbsentScopeFindings :many
-- Only findings the current report proves it looked for are locked.
-- Lock before retiring scope rows so concurrent scoped upserts cannot be lost.
SELECT f.id
FROM findings f
JOIN finding_scope_severities s ON s.finding_id = f.id
LEFT JOIN reports prior ON prior.id = s.report_id
JOIN reports current ON current.id = sqlc.arg(report_id)
WHERE f.project_id = sqlc.arg(project_id)
  AND s.scope_hash = sqlc.arg(scope_hash)
  AND report_examined_finding(current.scan_completeness, current.covered_finding_kinds, current.examined_keys, current.filter_severities, current.filter_fixable_only, current.scan_scope_hash, f.id, f.finding_kind, f.fingerprint)
  AND ((s.report_id IS NULL AND s.observed_at <= current.created_at)
       OR (prior.created_at, prior.id) < (current.created_at, current.id))
  AND NOT EXISTS (
      SELECT 1 FROM finding_occurrences o
      WHERE o.finding_id = f.id AND o.report_id = current.id
  )
ORDER BY f.id
FOR UPDATE OF f;

-- name: RetireAbsentScopeSeverities :exec
DELETE FROM finding_scope_severities s
WHERE s.finding_id = ANY(sqlc.arg(finding_ids)::uuid[])
  AND s.scope_hash = sqlc.arg(scope_hash)
  AND EXISTS (
      SELECT 1 FROM reports current
      LEFT JOIN reports prior ON prior.id = s.report_id
      WHERE current.id = sqlc.arg(report_id)
        AND ((s.report_id IS NULL AND s.observed_at <= current.created_at)
             OR (prior.created_at, prior.id) < (current.created_at, current.id))
  );

-- name: RetireScopeSeverityWithoutEvidence :exec
-- A report delete removes the scope row it supplied when no remaining report
-- in that scope observed the finding after the scope last scanned clean. A
-- clean scan is a completed, complete full report of the scope that covered
-- the finding's kind and does not observe it: ingest retired the row then,
-- and older evidence must not bring it back. Findings with other scopes keep
-- those rows; a finding with no scope at all keeps its historical severity.
DELETE FROM finding_scope_severities s
USING findings f
WHERE f.id = s.finding_id
  AND s.finding_id = ANY(sqlc.arg(finding_ids)::uuid[])
  AND s.scope_hash = sqlc.arg(scope_hash)
  AND NOT EXISTS (
      SELECT 1 FROM finding_occurrences o
      JOIN reports r ON r.id = o.report_id
      WHERE o.finding_id = s.finding_id
        AND COALESCE(r.scan_scope_hash, '') = s.scope_hash
        AND NOT EXISTS (
            SELECT 1 FROM reports clean
            WHERE clean.project_id = r.project_id
              AND clean.scan_scope_hash = s.scope_hash
              AND clean.status = 'completed'
              AND clean.scan_mode = 'full'
              AND report_examined_finding(clean.scan_completeness, clean.covered_finding_kinds, clean.examined_keys, clean.filter_severities, clean.filter_fixable_only, clean.scan_scope_hash, f.id, f.finding_kind, f.fingerprint)
              AND (clean.created_at, clean.id) > (r.created_at, r.id)
              AND NOT EXISTS (
                  SELECT 1 FROM finding_occurrences seen
                  WHERE seen.finding_id = s.finding_id AND seen.report_id = clean.id
              )
        )
  );

-- name: RestoreScopeSeverityFromNewestEvidence :exec
-- A report delete that leaves other reports in the same scope puts the
-- newest remaining observation back into the scope row, so the aggregate
-- reflects live evidence rather than the deleted report.
UPDATE finding_scope_severities s
SET severity = newest.severity,
    severity_rank = newest.severity_rank,
    report_id = newest.report_id,
    observed_at = newest.observed_at
FROM (
    SELECT DISTINCT ON (o.finding_id) o.finding_id, o.severity,
           o.severity_rank, o.report_id, o.observed_at
    FROM finding_occurrences o
    JOIN reports r ON r.id = o.report_id
    WHERE o.finding_id = ANY(sqlc.arg(finding_ids)::uuid[])
      AND COALESCE(r.scan_scope_hash, '') = sqlc.arg(scope_hash)
    ORDER BY o.finding_id, o.observed_at DESC, o.id DESC
) newest
WHERE s.finding_id = newest.finding_id
  AND s.scope_hash = sqlc.arg(scope_hash);

-- name: RefreshFindingScopeSeverities :exec
-- A finding with no remaining scope keeps its historical severity.
UPDATE findings f
SET current_severity = highest.severity,
    current_severity_rank = highest.severity_rank
FROM (
    SELECT DISTINCT ON (finding_id) finding_id, severity, severity_rank
    FROM finding_scope_severities
    WHERE finding_id = ANY($1::uuid[])
    ORDER BY finding_id, severity_rank DESC, scope_hash
) highest
WHERE f.id = highest.finding_id;

-- name: MarkAbsentScopedFindingsFixed :many
-- Scan-equivalence auto-fix: closes findings that an equivalent complete
-- scan of the same scope observed, that no scope still observes, and that
-- the current report no longer observes. A scope row is retired only by
-- a newer complete scan of that scope without the finding, so no rows left
-- means every scope that saw it has since scanned clean. The observation in
-- this scope keeps a clean scan of a branch that never saw the finding from
-- closing it, and nothing may be newer than the current report. The current
-- report must prove it looked for the finding: its kind is covered by a
-- complete report, or its own examined keys name the finding, and the finding
-- is inside the report's declared severity and fixable filter. Incremental
-- scans never reach this query, and a partial report proves nothing.
UPDATE findings
SET state = 'fixed', updated_at = NOW()
WHERE findings.project_id = sqlc.arg(project_id)
  AND findings.state IN ('open', 'reopened')
  AND EXISTS (
      SELECT 1 FROM reports examiner
      WHERE examiner.id = sqlc.arg(report_id)
        AND report_examined_finding(examiner.scan_completeness, examiner.covered_finding_kinds, examiner.examined_keys, examiner.filter_severities, examiner.filter_fixable_only, examiner.scan_scope_hash, findings.id, findings.finding_kind, findings.fingerprint)
  )
  AND NOT EXISTS (SELECT 1 FROM finding_scope_severities s WHERE s.finding_id = findings.id)
  AND NOT EXISTS (
      SELECT 1 FROM finding_occurrences occ
      WHERE occ.finding_id = findings.id
        AND occ.report_id = sqlc.arg(report_id)
  )
  AND EXISTS (
      SELECT 1 FROM finding_occurrences fo
      JOIN reports r ON r.id = fo.report_id
      WHERE fo.finding_id = findings.id
        AND r.scan_scope_hash = sqlc.arg(scan_scope_hash)
        AND r.scan_completeness <> 'partial'
        AND r.status = 'completed'
  )
  AND NOT EXISTS (
      SELECT 1 FROM finding_occurrences nf
      JOIN reports nr ON nr.id = nf.report_id
      JOIN reports current ON current.id = sqlc.arg(report_id)
      WHERE nf.finding_id = findings.id
        AND (nr.created_at, nr.id) > (current.created_at, current.id)
  )
RETURNING *;

-- name: ListFindingScopeSeverities :many
-- One row per (finding, scope) for the given findings. Ingest reads them to
-- find what each other scope last reported before it writes the project-wide
-- severity.
SELECT finding_id, scope_hash, severity, severity_rank, observed_at
FROM finding_scope_severities
WHERE finding_id = ANY($1::uuid[]);

-- name: UpsertFindingScopeSeverity :exec
-- Records the severity one scan scope reported for a finding. A repeat from
-- the same scope replaces the row.
INSERT INTO finding_scope_severities (
    finding_id, scope_hash, severity, severity_rank, report_id, observed_at
) VALUES (
    $1, $2, $3, $4, $5, $6
) ON CONFLICT (finding_id, scope_hash) DO UPDATE SET
    severity = EXCLUDED.severity,
    severity_rank = EXCLUDED.severity_rank,
    report_id = EXCLUDED.report_id,
    observed_at = EXCLUDED.observed_at;

-- name: BulkUpsertFindingScopeSeverities :exec
-- One scope row per finding for a whole ingest, in one statement. The caller
-- passes each (finding, scope) pair at most once, because a statement cannot
-- upsert the same key twice.
INSERT INTO finding_scope_severities (
    finding_id, scope_hash, severity, severity_rank, report_id, observed_at
)
SELECT fid.val, sh.val, sv.val, sr.val, rid.val, oa.val
FROM unnest($1::uuid[]) WITH ORDINALITY AS fid(val, ord)
JOIN unnest($2::text[]) WITH ORDINALITY AS sh(val, ord) ON fid.ord = sh.ord
JOIN unnest($3::text[]) WITH ORDINALITY AS sv(val, ord) ON fid.ord = sv.ord
JOIN unnest($4::smallint[]) WITH ORDINALITY AS sr(val, ord) ON fid.ord = sr.ord
JOIN unnest($5::uuid[]) WITH ORDINALITY AS rid(val, ord) ON fid.ord = rid.ord
JOIN unnest($6::timestamptz[]) WITH ORDINALITY AS oa(val, ord) ON fid.ord = oa.ord
ON CONFLICT (finding_id, scope_hash) DO UPDATE SET
    severity = EXCLUDED.severity,
    severity_rank = EXCLUDED.severity_rank,
    report_id = EXCLUDED.report_id,
    observed_at = EXCLUDED.observed_at;
