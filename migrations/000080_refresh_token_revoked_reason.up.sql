-- Why a refresh token stopped working. A refresh that presents a revoked token
-- reads it to tell a replay from a revocation the person caused themselves.
--
--   rotated           a refresh spent the token and stored its successor
--   logout            the person signed out of this sign-in
--   reuse             a spent token came back, so its sign-in chain was revoked
--   password_changed  a new password was set: a change, a reset link or the
--                     host-side recovery
--   sso_linked        an SSO login linked the account and removed its password
--   deactivated       an admin deactivated the account
--
-- NULL is a token revoked before this column existed. It reads as a replay,
-- the answer every revoked token got before.
ALTER TABLE refresh_tokens
    ADD COLUMN revoked_reason TEXT
        CONSTRAINT refresh_tokens_revoked_reason_check
        CHECK (revoked_reason IN ('rotated', 'logout', 'reuse', 'password_changed', 'sso_linked', 'deactivated'));

-- Applying this migration again after its down restores the reasons the down
-- kept in migration_000080_refresh_token_reasons, then drops that table. A
-- token revoked while the migration was rolled back has no reason on record
-- and reads as a replay.
DO $$
BEGIN
    IF to_regclass('migration_000080_refresh_token_reasons') IS NOT NULL THEN
        UPDATE refresh_tokens r
        SET revoked_reason = b.revoked_reason
        FROM migration_000080_refresh_token_reasons b
        WHERE r.id = b.id;
        DROP TABLE migration_000080_refresh_token_reasons;
    END IF;
END $$;
