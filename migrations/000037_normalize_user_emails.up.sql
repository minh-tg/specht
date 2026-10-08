-- Email identity is case-insensitive. Register and Login already lowercase,
-- but the SSO and admin-bootstrap paths did not, and the unique constraint and
-- lookups were case-sensitive, so one person could end up with two accounts.
--
-- Refuse to run when case-only duplicates already exist: choosing which
-- account survives is an operator decision, not something to guess here.
-- Resolve the listed addresses (merge or delete one of each pair), then
-- re-run; if the migration tool marked the database dirty, `migrate force 36`
-- first.
DO $$
DECLARE
    dup text;
BEGIN
    SELECT string_agg(e, ', ') INTO dup
    FROM (
        SELECT lower(email) AS e
        FROM users
        GROUP BY lower(email)
        HAVING count(*) > 1
    ) d;

    IF dup IS NOT NULL THEN
        RAISE EXCEPTION 'cannot normalise user emails: case-insensitive duplicates exist (%); merge or delete one account of each pair first', dup;
    END IF;
END $$;

-- Lowercasing discards the original casing. Keep it for rolled-back releases
-- (see migrations/POLICY.md): this backup holds only the rows that change and
-- is dropped by the down migration once the values are restored.
CREATE TABLE IF NOT EXISTS migration_000037_user_email_original (
    id UUID PRIMARY KEY,
    email TEXT NOT NULL
);

INSERT INTO migration_000037_user_email_original (id, email)
SELECT id, email FROM users WHERE email <> lower(email)
ON CONFLICT (id) DO NOTHING;

UPDATE users SET email = lower(email) WHERE email <> lower(email);

CREATE UNIQUE INDEX users_email_lower_key ON users (lower(email));
