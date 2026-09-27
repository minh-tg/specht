CREATE TABLE revoked_access_tokens (
    jti TEXT PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX revoked_access_tokens_expires_at_idx
    ON revoked_access_tokens (expires_at);
