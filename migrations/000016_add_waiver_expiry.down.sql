DROP INDEX IF EXISTS idx_waivers_expiry;

ALTER TABLE waivers DROP COLUMN IF EXISTS expires_at;
