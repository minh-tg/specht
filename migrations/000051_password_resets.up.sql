-- A password reset link lets an administrator hand a person a way back into
-- their account when no mail transport exists. Only a SHA-256 of the token is
-- stored, so a database read does not hand out working links. A link works
-- once, and issuing a new one for the same account retires the older ones.
CREATE TABLE password_resets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash TEXT NOT NULL UNIQUE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    CHECK (expires_at > created_at)
);

CREATE INDEX idx_password_resets_user_pending
    ON password_resets (user_id)
    WHERE used_at IS NULL AND revoked_at IS NULL;
