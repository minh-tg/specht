-- name: UpsertReportPackages :exec
INSERT INTO report_packages (
    report_id, purl, ecosystem, name, version, manifest_path
) VALUES (
    $1, $2, $3, $4, $5, $6
)
ON CONFLICT (report_id, purl) DO UPDATE SET
    last_seen_at = NOW();

-- name: DistinctInventory :many
-- One row per (project_id, purl): duplicate purls across reports collapse, and
-- the freshest sighting (last_seen_at DESC) wins the row. ORDER BY must lead
-- with the DISTINCT ON expressions per Postgres rules.
SELECT DISTINCT ON (r.project_id, rp.purl)
    r.project_id,
    rp.purl,
    rp.ecosystem,
    rp.name,
    rp.version,
    rp.last_seen_at
FROM report_packages rp
JOIN reports r ON r.id = rp.report_id
WHERE r.project_id = sqlc.arg(project_id)
  AND rp.last_seen_at >= NOW() - sqlc.arg(since)::interval
ORDER BY r.project_id, rp.purl, rp.last_seen_at DESC;

-- name: DeleteReportPackages :exec
DELETE FROM report_packages WHERE report_id = $1;
