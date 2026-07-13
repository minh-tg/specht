CREATE TABLE evidence_artifacts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    type TEXT NOT NULL CHECK (type IN ('screenshot', 'log', 'reference', 'automated')),
    url TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    uploaded_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_evidence_finding_id ON evidence_artifacts(finding_id);
