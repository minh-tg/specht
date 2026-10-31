-- decision_reason tells a machine outcome from a human one. The lifecycle sweep
-- sets 'expired' on a request it rejects because it outlived its expiry;
-- a reviewer's decision leaves it NULL.
ALTER TABLE waivers
    ADD COLUMN decision_reason TEXT
        CHECK (decision_reason IS NULL OR decision_reason IN ('expired'));

-- Requests the sweep already rejected carry its fixed note, so they backfill.
UPDATE waivers SET decision_reason = 'expired'
WHERE status = 'rejected'
  AND decision_note = 'expired before a decision';
