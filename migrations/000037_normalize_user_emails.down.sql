DROP INDEX IF EXISTS users_email_lower_key;

-- Restore the original casing recorded by the up migration. Accounts created
-- after it keep their lowercase address.
UPDATE users u
SET email = b.email
FROM migration_000037_user_email_original b
WHERE u.id = b.id;

DROP TABLE IF EXISTS migration_000037_user_email_original;
