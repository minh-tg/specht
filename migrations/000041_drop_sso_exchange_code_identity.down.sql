ALTER TABLE sso_exchange_codes
    ADD COLUMN email TEXT NOT NULL DEFAULT '',
    ADD COLUMN role TEXT NOT NULL DEFAULT 'member';
