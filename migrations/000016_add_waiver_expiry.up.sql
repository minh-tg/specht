ALTER TABLE waivers ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_waivers_expiry ON waivers(expires_at) WHERE enabled = true AND expires_at IS NOT NULL;
