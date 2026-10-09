-- Per-account access-token generation. Every access token carries the value
-- that was current when it was minted; bumping it invalidates all of that
-- account's outstanding access tokens at once, without tracking their IDs.
ALTER TABLE users ADD COLUMN token_version INTEGER NOT NULL DEFAULT 0;
