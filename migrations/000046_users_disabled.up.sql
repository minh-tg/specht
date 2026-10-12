-- A deactivated account keeps its history and memberships but cannot sign in.
ALTER TABLE users ADD COLUMN disabled_at TIMESTAMPTZ;
