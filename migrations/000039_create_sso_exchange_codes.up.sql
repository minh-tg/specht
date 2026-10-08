CREATE TABLE sso_exchange_codes (
    code_hash TEXT PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    role TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX sso_exchange_codes_expires_at_idx
    ON sso_exchange_codes (expires_at);
