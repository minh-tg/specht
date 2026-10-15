-- Values that belong to one installation and must survive restarts and restores,
-- such as the key that finding identities for secrets are hashed with. They live
-- in the database so a backup carries them: a restore with a different key would
-- give every secret finding a new identity.
CREATE TABLE instance_secrets (
    name TEXT PRIMARY KEY,
    value BYTEA NOT NULL CHECK (length(value) > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
