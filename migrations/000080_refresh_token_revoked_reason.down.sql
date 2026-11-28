-- The recorded reasons are kept so that applying 000080 again restores them.
-- Without the copy, a token a password change revoked would come back with no
-- reason, and its next refresh would read as a replay and tell the person a
-- token was stolen. The up migration restores from this table and drops it;
-- rows the token sweeper deletes in between are not restored.
DROP TABLE IF EXISTS migration_000080_refresh_token_reasons;
CREATE TABLE migration_000080_refresh_token_reasons AS
SELECT id, revoked_reason
FROM refresh_tokens
WHERE revoked_reason IS NOT NULL;

ALTER TABLE refresh_tokens
    DROP CONSTRAINT IF EXISTS refresh_tokens_revoked_reason_check,
    DROP COLUMN IF EXISTS revoked_reason;
