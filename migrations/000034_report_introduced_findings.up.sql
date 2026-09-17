-- Report-level introduced findings (RFC 0002): materializes the differential
-- finding set introduced by a specific report relative to its baseline.
-- Decouples transient change-scoped PR gating from global finding state.
CREATE TABLE report_introduced_findings (
    report_id UUID NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    baseline_report_id UUID REFERENCES reports(id) ON DELETE SET NULL,
    change_type TEXT NOT NULL DEFAULT 'new' CHECK (change_type IN ('new', 'regression')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (report_id, finding_id)
);

CREATE INDEX IF NOT EXISTS report_introduced_findings_report_id_idx
ON report_introduced_findings (report_id);

CREATE INDEX IF NOT EXISTS findings_project_intro_sha_idx
ON findings (project_id, introduced_commit_sha)
WHERE introduced_commit_sha IS NOT NULL;
