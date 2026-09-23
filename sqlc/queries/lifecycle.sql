-- name: ExpireFindings :many
WITH expired AS (
    SELECT id, project_id, analysis_state, gate_effect
    FROM findings
    WHERE analysis_expires_at IS NOT NULL
      AND analysis_expires_at <= NOW()
    FOR UPDATE
)
UPDATE findings SET
    analysis_state = 'unanalyzed',
    gate_effect = 'block',
    analysis_expires_at = NULL,
    analysis_updated_at = NOW(),
    updated_at = NOW()
FROM expired
WHERE findings.id = expired.id
RETURNING expired.id, expired.project_id,
    expired.analysis_state AS old_analysis_state,
    expired.gate_effect AS old_gate_effect,
    findings.analysis_state, findings.gate_effect;
