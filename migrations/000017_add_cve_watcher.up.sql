CREATE TABLE IF NOT EXISTS report_packages (
    report_id UUID NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
    purl TEXT NOT NULL,
    ecosystem TEXT,
    name TEXT,
    version TEXT,
    manifest_path TEXT,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (report_id, purl)
);

INSERT INTO finding_kinds (code, label, description) VALUES
    ('cve_watcher', 'CVE Watcher', 'Findings from the CVE feed watcher')
ON CONFLICT (code) DO NOTHING;

CREATE TABLE IF NOT EXISTS watcher_state (
    id INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    last_successful_poll_at TIMESTAMPTZ
);

ALTER TABLE projects
    ADD COLUMN IF NOT EXISTS cve_watcher_gate TEXT NOT NULL DEFAULT 'require_triage'
    CHECK (cve_watcher_gate IN ('require_triage', 'immediate', 'off'));
