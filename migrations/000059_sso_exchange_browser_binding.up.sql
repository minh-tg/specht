-- An exchange code remembers the browser that started its login: a hash of the
-- login cookie's secret. The exchange refuses a code from any other browser.
-- Codes live 60 seconds and are pruned, so a row written before this migration
-- has an empty binding, which matches no browser and is refused.
ALTER TABLE sso_exchange_codes ADD COLUMN browser_binding TEXT NOT NULL DEFAULT '';
