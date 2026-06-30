CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    finding_kind TEXT NOT NULL REFERENCES finding_kinds(code),
    fingerprint TEXT NOT NULL,
    current_title TEXT NOT NULL,
    current_severity TEXT NOT NULL,
    current_severity_rank SMALLINT NOT NULL,
    current_score NUMERIC(4,1),
    state TEXT NOT NULL DEFAULT 'open'
        CHECK (state IN ('open', 'fixed', 'reopened')),
    triage_status TEXT NOT NULL DEFAULT 'untriaged'
        CHECK (triage_status IN ('untriaged', 'confirmed', 'false_positive', 'wont_fix')),
    assignee_id UUID REFERENCES users(id),
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    fixed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(project_id, finding_kind, fingerprint)
);

CREATE INDEX idx_findings_state ON findings(project_id, state, current_severity_rank);
CREATE INDEX idx_findings_kind ON findings(project_id, finding_kind);
CREATE INDEX idx_findings_fp ON findings(project_id, fingerprint);

CREATE TABLE finding_occurrences (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    report_id UUID NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL,
    severity_rank SMALLINT NOT NULL,
    score NUMERIC(4,1),
    tool_name TEXT NOT NULL,
    tool_version TEXT,
    parser_version TEXT,
    location_summary TEXT,
    subject_summary TEXT,
    remediation TEXT,
    display JSONB NOT NULL DEFAULT '{}',
    metadata JSONB NOT NULL DEFAULT '{}',
    observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(finding_id, report_id)
);

CREATE INDEX idx_occ_finding ON finding_occurrences(finding_id, observed_at DESC);
CREATE INDEX idx_occ_report ON finding_occurrences(report_id);

CREATE TABLE finding_dimensions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    dim_key TEXT NOT NULL,
    dim_value TEXT NOT NULL,
    source TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(finding_id, dim_key, dim_value)
);

CREATE INDEX idx_dim_lookup ON finding_dimensions(dim_key, dim_value);
CREATE INDEX idx_dim_finding ON finding_dimensions(finding_id);
