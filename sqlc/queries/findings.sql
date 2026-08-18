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
-- re-poll hits of an existing watcher finding (the
-- UNIQUE(finding_id, report_id) constraint does not dedupe NULL report_ids).
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
) ON CONFLICT (finding_id, report_id) DO NOTHING
RETURNING *;

-- name: ListFindingsByProject :many
SELECT * FROM findings
WHERE project_id = $1
  AND (array_length($2::text[], 1) IS NULL OR current_severity = ANY($2))
  AND (array_length($3::text[], 1) IS NULL OR state = ANY($3))
  AND (array_length($4::text[], 1) IS NULL OR finding_kind = ANY($4))
ORDER BY current_severity_rank DESC, created_at DESC
LIMIT $5 OFFSET $6;

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

-- name: GateEval :one
SELECT EXISTS (
    SELECT 1
    FROM findings f
    JOIN projects p ON p.id = f.project_id
    WHERE f.project_id = $1
      AND f.state IN ('open', 'reopened')
      AND f.current_severity_rank >= $2
      AND (
          f.gate_effect = 'block'
          OR f.review_required = true
          OR (
              f.gate_effect = 'ignore'
              AND f.analysis_expires_at IS NOT NULL
              AND f.analysis_expires_at <= NOW()
          )
      )
      -- CVE watcher gate policy: cve_watcher findings gate only when the
      -- project's cve_watcher_gate mode admits them. 'immediate' admits all;
      -- 'off' admits none; 'require_triage' (the column default) admits only
      -- watcher findings that have been triaged (analysis_state set, i.e. no
      -- longer 'unanalyzed' — the "untriaged" marker from migration 000009).
      -- Additive by construction: non-watcher findings pass through
      -- unchanged in every mode, so behavior at the default is identical to
      -- the pre-gate-policy queries.
      AND (
          p.cve_watcher_gate = 'immediate'
          OR f.finding_kind <> 'cve_watcher'
          OR (
              p.cve_watcher_gate = 'require_triage'
              AND f.analysis_state <> 'unanalyzed'
          )
      )
) AS threshold_breached;

-- name: CountBlockingFindings :one
SELECT COUNT(*) FROM findings f
JOIN projects p ON p.id = f.project_id
WHERE f.project_id = $1
  AND f.state IN ('open', 'reopened')
  AND f.current_severity_rank >= $2
  AND (
      f.gate_effect = 'block'
      OR f.review_required = true
      OR (
          f.gate_effect = 'ignore'
          AND f.analysis_expires_at IS NOT NULL
          AND f.analysis_expires_at <= NOW()
      )
  )
  AND (
      p.cve_watcher_gate = 'immediate'
      OR f.finding_kind <> 'cve_watcher'
      OR (
          p.cve_watcher_gate = 'require_triage'
          AND f.analysis_state <> 'unanalyzed'
      )
  );

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

-- name: HasDimension :one
SELECT EXISTS (
    SELECT 1 FROM finding_dimensions
    WHERE finding_id = $1 AND dim_key = $2 AND dim_value != ''
) AS exists;

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
-- finding (skip-event resolution: the decision conveys the skip but not
-- the suppressing id — the wiring re-uses this query to resolve it).
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
