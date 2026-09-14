-- Organization-wide policy templates (SOLO-185): reusable baselines a
-- platform team applies to many repositories. Projects link a template and
-- override individual keys in their settings JSON; effective resolution is
-- template <- project override <- built-in default, with per-key provenance
-- so developers can see which policy caused a gate. Waivers remain the
-- exception mechanism (owner, reason, expiry already live there).
CREATE TABLE policy_templates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    definition JSONB NOT NULL DEFAULT '{}',
    version INT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE projects
ADD COLUMN policy_template_id UUID REFERENCES policy_templates(id) ON DELETE SET NULL;
