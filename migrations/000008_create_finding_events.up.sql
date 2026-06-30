CREATE TABLE finding_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id),
    event_type TEXT NOT NULL CHECK (event_type IN
        ('state_changed', 'triage_changed', 'assigned', 'commented')),
    old_value TEXT,
    new_value TEXT,
    comment TEXT,
    changes JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_fe_finding ON finding_events(finding_id, created_at DESC);
