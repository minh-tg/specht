-- name: ListLatestCVEOccurrences :many
-- The newest occurrence per tool for one finding, newest first. Watcher
-- occurrences have no report, so this must not join reports: an inner join
-- would drop exactly the findings the CVE watcher created.
SELECT * FROM (
    SELECT DISTINCT ON (fo.tool_name)
        fo.tool_name, fo.report_id, fo.observed_at, fo.metadata
    FROM finding_occurrences fo
    WHERE fo.finding_id = $1
    ORDER BY fo.tool_name, fo.observed_at DESC, fo.id DESC
) latest
ORDER BY latest.observed_at DESC, latest.tool_name
LIMIT 16;

-- name: ListCVEDetailCache :many
SELECT provider, cve_id, status, record, fetched_at, expires_at, lease_until
FROM cve_detail_cache
WHERE cve_id = $1;

-- name: AcquireCVEDetailLease :one
-- Takes the fetch lease for one provider and CVE. It succeeds when no row
-- exists (a 'pending' placeholder is written), or when the row is a pending
-- placeholder or an expired answer and no other replica holds a current
-- lease. No row comes back when the lease is taken or the answer is fresh.
INSERT INTO cve_detail_cache (provider, cve_id, status, fetched_at, expires_at, lease_until)
VALUES (sqlc.arg(provider), sqlc.arg(cve_id), 'pending', sqlc.arg(now), sqlc.arg(now), sqlc.arg(lease_until))
ON CONFLICT (provider, cve_id) DO UPDATE SET lease_until = EXCLUDED.lease_until
WHERE (cve_detail_cache.lease_until IS NULL OR cve_detail_cache.lease_until <= sqlc.arg(now))
    AND (cve_detail_cache.status = 'pending' OR cve_detail_cache.expires_at <= sqlc.arg(now))
RETURNING provider;

-- name: StoreCVEDetail :exec
-- Writes a provider answer and releases the lease in the same statement.
INSERT INTO cve_detail_cache (provider, cve_id, status, record, fetched_at, expires_at, lease_until)
VALUES ($1, $2, $3, $4, $5, $6, NULL)
ON CONFLICT (provider, cve_id) DO UPDATE SET
    status = EXCLUDED.status,
    record = EXCLUDED.record,
    fetched_at = EXCLUDED.fetched_at,
    expires_at = EXCLUDED.expires_at,
    lease_until = NULL;

-- name: DeletePendingCVEDetail :exec
-- Drops the placeholder of a first fetch that failed, so no row claims an
-- answer that never came.
DELETE FROM cve_detail_cache
WHERE provider = $1 AND cve_id = $2 AND status = 'pending';

-- name: ReleaseCVEDetailLease :exec
UPDATE cve_detail_cache SET lease_until = NULL
WHERE provider = $1 AND cve_id = $2;

-- name: SweepCVEDetailCache :execrows
-- Deletes answers that expired before the cutoff and are not being refetched.
DELETE FROM cve_detail_cache
WHERE expires_at < sqlc.arg(cutoff)
    AND (lease_until IS NULL OR lease_until < NOW());

-- name: RecordCVEProviderSuccess :exec
INSERT INTO cve_provider_status (provider, last_success_at)
VALUES ($1, $2)
ON CONFLICT (provider) DO UPDATE SET last_success_at = EXCLUDED.last_success_at;

-- name: RecordCVEProviderError :exec
-- GREATEST ignores NULL, so a plain error never shortens a rate-limit backoff
-- another replica recorded.
INSERT INTO cve_provider_status (provider, last_error_at, last_error, backoff_until)
VALUES ($1, $2, $3, $4)
ON CONFLICT (provider) DO UPDATE SET
    last_error_at = EXCLUDED.last_error_at,
    last_error = EXCLUDED.last_error,
    backoff_until = GREATEST(cve_provider_status.backoff_until, EXCLUDED.backoff_until);

-- name: ListCVEProviderStatus :many
SELECT provider, last_success_at, last_error_at, last_error, backoff_until
FROM cve_provider_status
ORDER BY provider;
