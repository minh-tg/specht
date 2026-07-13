CREATE TABLE reachability_assessments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    reachable BOOLEAN NOT NULL,
    evidence TEXT NOT NULL DEFAULT '',
    assessed_by UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (finding_id, assessed_by)
);

CREATE INDEX idx_reachability_finding_id ON reachability_assessments(finding_id);
