-- The column holds codes that expire within 60 seconds, so dropping it discards
-- nothing that outlives the rollback window.
ALTER TABLE sso_exchange_codes DROP COLUMN browser_binding;
