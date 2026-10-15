-- CVE details fetched from external providers (NVD, VulnCheck, OSV) for CVEs
-- whose scan report lacks a usable CVSS vector, a CWE or a published date.
-- One row per provider and CVE. A 'found' row carries the normalized record,
-- a 'not_found' row is the negative cache, and a 'pending' row is the
-- placeholder a replica writes to hold the fetch lease before the first
-- answer exists. Rows are swept 30 days after they expire.
CREATE TABLE cve_detail_cache (
    provider TEXT NOT NULL,
    cve_id TEXT NOT NULL CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,7}$'),
    status TEXT NOT NULL CHECK (status IN ('found', 'not_found', 'pending')),
    -- The normalized record; the application refuses records over 64 KiB.
    record JSONB,
    fetched_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    -- Cross-replica single flight: the replica whose lease is current fetches.
    lease_until TIMESTAMPTZ,
    PRIMARY KEY (provider, cve_id),
    CHECK (status <> 'found' OR record IS NOT NULL)
);

CREATE INDEX idx_cve_detail_cache_expires ON cve_detail_cache (expires_at);
CREATE INDEX idx_cve_detail_cache_cve ON cve_detail_cache (cve_id);

-- The last outcome per provider, for the admin status page and the shared
-- backoff after a rate limit. last_error is a fixed category, never the
-- provider's message, so no response text or key can land here.
CREATE TABLE cve_provider_status (
    provider TEXT PRIMARY KEY,
    last_success_at TIMESTAMPTZ,
    last_error_at TIMESTAMPTZ,
    last_error TEXT CHECK (last_error IN ('timeout', 'rate_limited', 'http_4xx', 'http_5xx', 'decode', 'too_large', 'tls', 'network')),
    backoff_until TIMESTAMPTZ
);
