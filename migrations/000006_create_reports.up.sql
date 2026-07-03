CREATE TABLE reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    tool_name TEXT NOT NULL,
    tool_version TEXT,
    scan_type TEXT NOT NULL CHECK (scan_type IN (
        'image', 'filesystem', 'repository', 'sbom', 'sarif', 'iac', 'lockfile'
    )),
    target_id UUID REFERENCES targets(id),
    artifact_id UUID REFERENCES artifacts(id),
    environment_id UUID REFERENCES environments(id),
    scan_target TEXT,
    scan_scope JSONB NOT NULL DEFAULT '{}',
    scan_scope_hash TEXT,
    scan_completeness TEXT NOT NULL DEFAULT 'unknown'
        CHECK (scan_completeness IN ('complete', 'partial', 'unknown')),
    scanner_config_hash TEXT,
    branch TEXT,
    commit_sha TEXT,
    status TEXT NOT NULL DEFAULT 'processing'
        CHECK (status IN ('processing', 'completed', 'failed')),
    total_findings INTEGER DEFAULT 0,
    parser_version TEXT,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    error_message TEXT,
    raw_report_hash TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_reports_dedup
    ON reports(project_id, raw_report_hash)
    WHERE raw_report_hash IS NOT NULL AND status = 'completed';

CREATE INDEX idx_reports_project ON reports(project_id, created_at DESC);
