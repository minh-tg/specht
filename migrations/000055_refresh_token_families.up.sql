-- A refresh token family is the chain of tokens one sign-in produces through
-- rotation. family_started_at is the time of that original sign-in and is
-- copied unchanged on every rotation, so the server can end a session after an
-- absolute lifetime instead of renewing it forever. Revoking one family ends
-- one sign-in without touching the user's other devices.
--
-- Existing rows cannot be grouped into chains, so each takes its creation time
-- as the family start. They share one family per user (family_id = user_id,
-- which never collides with a random UUID): a replay of a legacy token still
-- revokes every legacy session of that user, the behavior before families
-- existed.
ALTER TABLE refresh_tokens ADD COLUMN family_id UUID;
ALTER TABLE refresh_tokens ADD COLUMN family_started_at TIMESTAMPTZ;

UPDATE refresh_tokens
SET family_id = user_id,
    family_started_at = created_at;

-- The defaults keep the previous release working against this schema (it
-- inserts refresh tokens without these columns, and a rolling upgrade runs both
-- versions at once): each such token becomes a family of its own, started now.
ALTER TABLE refresh_tokens ALTER COLUMN family_id SET DEFAULT gen_random_uuid();
ALTER TABLE refresh_tokens ALTER COLUMN family_started_at SET DEFAULT now();
ALTER TABLE refresh_tokens ALTER COLUMN family_id SET NOT NULL;
ALTER TABLE refresh_tokens ALTER COLUMN family_started_at SET NOT NULL;

CREATE INDEX idx_refresh_tokens_family ON refresh_tokens(family_id);
