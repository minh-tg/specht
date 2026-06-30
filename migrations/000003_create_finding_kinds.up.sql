CREATE TABLE finding_kinds (
    code TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO finding_kinds VALUES
    ('sca', 'Software Composition Analysis', 'Vulnerable dependencies'),
    ('sast', 'Static Analysis', 'Code-level security issues'),
    ('iac', 'Infrastructure as Code', 'Cloud/resource misconfigurations'),
    ('secret', 'Secret Exposure', 'Credentials found in code or artifacts'),
    ('image_config', 'Container Image Config', 'Unsafe image configuration'),
    ('license', 'License Finding', 'License/compliance issue');
