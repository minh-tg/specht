-- Fix: reachability/signoff/evidence assessed_by must reference a real user.
-- API keys are project-scoped credentials minted by a JWT user, but the
-- api_keys table never recorded who created them, so API-key-authenticated
-- writes had no users.id actor to attribute. Add created_by so the auth
-- lookup can resolve an API key to its owning user.

ALTER TABLE api_keys
    ADD COLUMN created_by UUID REFERENCES users(id);

-- Existing keys have no known creator; created_by stays NULL. Authentication
-- preserves read access, while actor-requiring writes reject these keys until
-- a key with a real owner is created.
