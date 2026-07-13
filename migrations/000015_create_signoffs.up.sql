CREATE TYPE signoff_status AS ENUM ('pending', 'approved', 'rejected');

CREATE TABLE signoffs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    status signoff_status NOT NULL DEFAULT 'pending',
    reviewed_by UUID NOT NULL REFERENCES users(id),
    comment TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (finding_id)
);
