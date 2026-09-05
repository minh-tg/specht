-- Remove the dormant approval columns from findings. approval_status,
-- approved_by, and approved_at were added by 000009 but never received a
-- writer: no ingest, triage, signoff, or lifecycle path sets them, and they
-- are not surfaced in any API response. Signoff review lives in the
-- dedicated signoffs table. Dropping dead schema rather than carrying it.
ALTER TABLE findings DROP COLUMN IF EXISTS approved_at;
ALTER TABLE findings DROP COLUMN IF EXISTS approved_by;
ALTER TABLE findings DROP COLUMN IF EXISTS approval_status;
