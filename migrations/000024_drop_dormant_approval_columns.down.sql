-- Restore the dormant approval columns dropped by the up migration.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS approval_status TEXT NOT NULL DEFAULT 'none'
  CHECK (approval_status IN ('none', 'required', 'approved', 'rejected'));

ALTER TABLE findings ADD COLUMN IF NOT EXISTS approved_by UUID REFERENCES users(id);

ALTER TABLE findings ADD COLUMN IF NOT EXISTS approved_at TIMESTAMPTZ;
