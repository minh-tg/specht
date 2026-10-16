-- The pruning sweep deletes rows that expired or were revoked a while ago.
-- These indexes let it find them without scanning the whole table.
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);
CREATE INDEX idx_refresh_tokens_revoked_at ON refresh_tokens(revoked_at) WHERE revoked_at IS NOT NULL;
