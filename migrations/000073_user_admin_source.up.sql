-- Where an account's global admin role came from. 'sso' is a grant by
-- SSO_ADMIN_GROUPS, which an SSO login without an admin group takes back.
-- 'manual' is everything else: first-run setup, ADMIN_EMAILS, the admin API
-- and the grant-admin command. Admins that existed before the source was
-- recorded count as manual, so an upgrade demotes nobody. The value only
-- matters while the role is admin.
ALTER TABLE users
    ADD COLUMN admin_source TEXT NOT NULL DEFAULT 'manual',
    ADD CONSTRAINT users_admin_source_check CHECK (admin_source IN ('manual', 'sso'));
