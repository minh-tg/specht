-- Waivers gain a review lifecycle. Rows that exist today were created by a
-- project admin and already count, so they backfill to 'approved'.
ALTER TABLE waivers
    ADD COLUMN status TEXT NOT NULL DEFAULT 'approved'
        CHECK (status IN ('pending', 'approved', 'rejected', 'withdrawn')),
    ADD COLUMN scope_all BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN reason TEXT NOT NULL DEFAULT '',
    ADD COLUMN requested_by UUID REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN requested_at TIMESTAMPTZ,
    ADD COLUMN decided_by UUID REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN decided_at TIMESTAMPTZ,
    ADD COLUMN decision_note TEXT NOT NULL DEFAULT '';

-- A waiver with no contexts, targets or conditions used to cover every
-- finding by default. Coverage of everything is now an explicit flag, and the
-- existing rows that relied on the default keep their behaviour.
UPDATE waivers w SET scope_all = true
WHERE NOT EXISTS (SELECT 1 FROM waiver_conditions c WHERE c.waiver_id = w.id)
  AND NOT EXISTS (SELECT 1 FROM waiver_contexts x WHERE x.waiver_id = w.id)
  AND NOT EXISTS (SELECT 1 FROM waiver_finding_targets t WHERE t.waiver_id = w.id);

CREATE INDEX idx_waivers_project_status ON waivers (project_id, status);
