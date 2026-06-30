CREATE TABLE environments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    tier TEXT NOT NULL CHECK (tier IN ('production', 'staging', 'development', 'test')),
    internet_facing BOOLEAN NOT NULL DEFAULT FALSE,
    data_sensitivity TEXT NOT NULL DEFAULT 'internal'
        CHECK (data_sensitivity IN ('public', 'internal', 'confidential', 'restricted')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(project_id, name)
);

CREATE TABLE targets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('repo', 'service', 'container_image', 'filesystem', 'iac_stack', 'package')),
    locator TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(project_id, name)
);

CREATE TABLE artifacts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    target_id UUID REFERENCES targets(id) ON DELETE SET NULL,
    artifact_type TEXT NOT NULL CHECK (artifact_type IN
        ('container_image', 'sbom', 'repository_snapshot', 'filesystem', 'sarif', 'iac_stack')),
    name TEXT NOT NULL,
    version TEXT,
    digest TEXT,
    locator TEXT,
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(project_id, artifact_type, name, digest)
);

CREATE UNIQUE INDEX idx_artifacts_digest_unique
    ON artifacts(project_id, artifact_type, digest)
    WHERE digest IS NOT NULL;
