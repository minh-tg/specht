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

-- name: UpsertDimension :one
INSERT INTO finding_dimensions (
    finding_id, dim_key, dim_value, source
) VALUES (
    $1, $2, $3, $4
) ON CONFLICT (finding_id, dim_key, dim_value) DO UPDATE SET
    source = EXCLUDED.source
RETURNING *;
