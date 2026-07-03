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
ORDER BY current_severity_rank DESC, created_at DESC
LIMIT $4 OFFSET $5;

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
    SELECT 1 FROM findings
    WHERE project_id = $1
      AND state IN ('open', 'reopened')
      AND current_severity_rank >= $2
      AND (
          gate_effect = 'block'
          OR review_required = true
          OR (
              gate_effect = 'ignore'
              AND analysis_expires_at IS NOT NULL
              AND analysis_expires_at <= NOW()
          )
      )
) AS threshold_breached;

-- name: CountBlockingFindings :one
SELECT COUNT(*) FROM findings
WHERE project_id = $1
  AND state IN ('open', 'reopened')
  AND current_severity_rank >= $2
  AND (
      gate_effect = 'block'
      OR review_required = true
      OR (
          gate_effect = 'ignore'
          AND analysis_expires_at IS NOT NULL
          AND analysis_expires_at <= NOW()
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
