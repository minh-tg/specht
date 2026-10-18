-- Exemption from the backup rule in POLICY.md, granted by the owner: the rows
-- are short-lived login codes in sso_exchange_codes that expire within 60
-- seconds, so dropping browser_binding discards nothing worth preserving.
ALTER TABLE sso_exchange_codes DROP COLUMN browser_binding;
