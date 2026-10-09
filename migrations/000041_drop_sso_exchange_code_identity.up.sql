-- The exchange code's email and role were written at creation and never read:
-- ExchangeSSOCode re-reads the account. Drop them so the table holds only what
-- the exchange depends on.
ALTER TABLE sso_exchange_codes DROP COLUMN email, DROP COLUMN role;
