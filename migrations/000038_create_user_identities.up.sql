-- Links an account to its identity at an external provider (SSO). The pair
-- (issuer, subject) is the stable identifier of a person at that provider; an
-- email claim is not, because providers let it change and some let a user
-- assert one they have not verified. Logins are matched on this pair.
--
-- UNIQUE (issuer, subject): one provider identity maps to at most one account.
-- UNIQUE (user_id, issuer): an account has at most one identity per provider,
-- so a second subject carrying the same email cannot be attached to it.
CREATE TABLE user_identities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (issuer, subject),
    UNIQUE (user_id, issuer)
);
