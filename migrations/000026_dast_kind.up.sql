-- DAST findings: dynamic analysis observations (Nuclei first). Identity is
-- template + target host; request/response bodies never enter the model
-- (see the nuclei adapter's RedactRaw) and live findings key on the URL
-- without query parameters so parameter fuzzing does not fork rows.
INSERT INTO finding_kinds (code, label, description) VALUES
    ('dast', 'Dynamic Analysis', 'Runtime-detected exposures from DAST tools')
ON CONFLICT (code) DO NOTHING;
