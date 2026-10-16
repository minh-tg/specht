-- Records that the account proved it owns its email address. Registering with
-- a password proves nothing, so ADMIN_EMAILS may only promote an account where
-- this is true: the one created by first-run setup, or one that signed in
-- through SSO while the identity provider vouched for the address.
--
-- The backfill marks every account that already has an SSO identity. The
-- column the identity table lacks is whether the provider vouched for the
-- email at link time, so an account linked under SSO_ALLOW_UNVERIFIED_EMAIL
-- is marked too. Existing admins are unaffected, because promotion skips
-- accounts that are already admins. The first-run setup account of an
-- existing install cannot be told apart from a registered one and stays
-- unmarked.
ALTER TABLE users ADD COLUMN email_proven BOOLEAN NOT NULL DEFAULT FALSE;

UPDATE users
SET email_proven = TRUE
WHERE EXISTS (SELECT 1 FROM user_identities i WHERE i.user_id = users.id);
