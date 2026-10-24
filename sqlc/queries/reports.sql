-- name: LockProjectIngest :exec
SELECT pg_advisory_xact_lock(hashtextextended('ingest:' || sqlc.arg(project_id)::text, 0));

-- name: CreateReport :one
INSERT INTO reports (
    project_id, tool_name, tool_version, scan_type,
    target_id, artifact_id, environment_id,
    scan_target, scan_scope, scan_scope_hash,
    scan_completeness, scanner_config_hash,
    branch, commit_sha, status,
    total_findings, parser_version,
    started_at, error_message, raw_report_hash,
    raw_data,
    base_revision, changed_files, scan_mode
) VALUES (
    $1, $2, $3, $4,
    $5, $6, $7,
    $8, $9, $10,
    $11, $12,
    $13, $14, $15,
    $16, $17,
    $18, $19, $20,
    $21,
    $22, $23, $24
) RETURNING *;

-- name: GetReportByID :one
SELECT * FROM reports WHERE id = $1;

-- name: ListReportsByProject :many
-- An empty branch or commit_sha selects every report. The default commit
-- match is exact; change pages explicitly request case-insensitive prefixes.
SELECT * FROM reports
WHERE project_id = $1
  AND (sqlc.arg(branch)::text = '' OR branch = sqlc.arg(branch)::text)
  AND (sqlc.arg(commit_sha)::text = '' OR
    CASE WHEN sqlc.arg(commit_prefix)::boolean
      THEN starts_with(lower(commit_sha), lower(sqlc.arg(commit_sha)::text))
      ELSE commit_sha = lower(sqlc.arg(commit_sha)::text)
    END)
ORDER BY created_at DESC, id DESC
LIMIT $2 OFFSET $3;

-- name: UpdateReportStatus :one
UPDATE reports SET
    status = $2,
    total_findings = $3,
    completed_at = CASE WHEN $2 = 'completed' OR $2 = 'failed' THEN NOW() ELSE completed_at END,
    error_message = $4
WHERE id = $1 AND project_id = $5
RETURNING *;
-- name: LatestCompletedReportByScanner :one
SELECT id, tool_name, branch, commit_sha, scan_completeness, created_at
FROM reports
WHERE project_id = $1 AND tool_name = $2 AND status = 'completed' AND scan_mode = 'full'
ORDER BY created_at DESC, id DESC
LIMIT 1;

-- name: GetCompletedReportByCommit :one
-- Baseline resolution for incremental analysis: the newest
-- completed same-scanner report for an exact revision. pgx.ErrNoRows means
-- no baseline exists for the base revision — the caller falls back to a
-- full scan instead of guessing.
SELECT id, tool_name, branch, commit_sha, base_revision, scan_mode, scan_completeness, created_at
FROM reports
WHERE project_id = $1 AND tool_name = $2 AND commit_sha = $3 AND status = 'completed' AND scan_mode = 'full'
ORDER BY created_at DESC, id DESC
LIMIT 1;

-- name: HasCompletedReportForCommit :one
-- Whether any scanner completed a scan of an exact revision. A PR check
-- needs this to tell a commit with no scan evidence from a scan that found
-- nothing new.
SELECT EXISTS (
    SELECT 1 FROM reports
    WHERE project_id = $1 AND commit_sha = $2 AND status = 'completed'
);

-- name: GetLatestCompletedFullReportByBranch :one
-- Baseline resolution when base_revision names a branch rather than a
-- commit: the newest completed full scan from the same scanner on that
-- branch. pgx.ErrNoRows means the branch has no full baseline yet.
SELECT id, tool_name, branch, commit_sha, base_revision, scan_mode, scan_completeness, created_at
FROM reports
WHERE project_id = $1 AND tool_name = $2 AND branch = $3 AND status = 'completed' AND scan_mode = 'full'
ORDER BY created_at DESC, id DESC
LIMIT 1;

-- name: LatestCompletedFullReportInFindingScope :one
-- Verification basis for one finding: the newest completed full report that
-- shares the scan scope of the report that most recently observed the finding.
-- Completeness is not filtered here: a partial report in that scope that still
-- observes the finding must be seen, and the caller decides what a partial
-- report can prove. Reports from other images, targets, or branches never
-- qualify. pgx.ErrNoRows means the finding has no observation in a report, or
-- no completed full report exists in that scope.
WITH latest_observation AS (
    SELECT r.scan_scope_hash
    FROM finding_occurrences fo
    JOIN reports r ON r.id = fo.report_id
    WHERE fo.finding_id = $2
    ORDER BY fo.observed_at DESC, r.id DESC
    LIMIT 1
)
SELECT r.id, r.tool_name, r.branch, r.commit_sha, r.base_revision, r.scan_mode, r.scan_completeness, r.created_at
FROM reports r
WHERE r.project_id = $1
  AND r.scan_scope_hash = (SELECT lo.scan_scope_hash FROM latest_observation lo)
  AND r.status = 'completed'
  AND r.scan_mode = 'full'
ORDER BY r.created_at DESC, r.id DESC
LIMIT 1;

-- name: FailStaleReports :many
-- A report stays in processing only while its ingest request runs. One that
-- is still there well after the ingest window means the server stopped under
-- it, so it is settled as failed and a retry can ingest the same content. The
-- ids come back so the findings it left half written can be settled too.
UPDATE reports SET
    status = 'failed',
    completed_at = NOW(),
    error_message = $2
WHERE status = 'processing'
  AND created_at < $1
RETURNING id, project_id;

-- name: DeleteFindingsOfFailedReport :many
-- An ingest upserts a finding row and attributes it to its report before it
-- writes the occurrences, so one that stops midway leaves findings no
-- occurrence supports. This removes the ones the failed report created itself
-- (born after the report, never triaged) and still has no occurrence. A
-- finding any other report has an occurrence for is not touched.
DELETE FROM findings f
USING reports r
WHERE r.id = sqlc.arg(report_id) AND r.project_id = sqlc.arg(project_id)
  AND r.status = 'failed'
  AND f.project_id = r.project_id
  AND f.introduced_by_report_id = r.id
  AND f.created_at >= r.created_at
  AND f.triage_status = 'untriaged'
  AND NOT EXISTS (SELECT 1 FROM finding_occurrences fo WHERE fo.finding_id = f.id)
RETURNING f.id;

-- name: ArchiveFindingsOfFailedReport :many
-- The other half of the cleanup: findings the failed report attributed to
-- itself and that have no occurrence, but that it did not create (it brought
-- an archived one back) or that someone already triaged. They are archived
-- like findings that lost their report, with an event naming the report.
WITH orphaned AS (
    SELECT f.id, f.state
    FROM findings f
    JOIN reports r ON r.id = f.introduced_by_report_id
    WHERE r.id = sqlc.arg(report_id) AND r.project_id = sqlc.arg(project_id)
      AND r.status = 'failed'
      AND f.project_id = r.project_id
      AND f.state IN ('open', 'reopened')
      AND NOT EXISTS (SELECT 1 FROM finding_occurrences fo WHERE fo.finding_id = f.id)
    FOR UPDATE OF f
), archived AS (
    UPDATE findings f
    SET state = 'archived', updated_at = NOW()
    FROM orphaned o
    WHERE f.id = o.id
    RETURNING f.id
), logged AS (
    INSERT INTO finding_events (finding_id, event_type, old_value, new_value, changes)
    SELECT o.id, 'state_changed', o.state, 'archived',
           jsonb_build_object('report_id', sqlc.arg(report_id)::text, 'reason', 'report_failed')
    FROM orphaned o
    JOIN archived a ON a.id = o.id
    RETURNING finding_id
)
SELECT finding_id FROM logged;

-- name: CountStaleReports :one
-- Retention preview: settled (completed/failed) reports older
-- than the cutoff. Processing reports are never counted — an in-flight
-- scan must not look purgable.
SELECT COUNT(*) FROM reports
WHERE status IN ('completed', 'failed')
  AND COALESCE(completed_at, created_at) < $1;

-- name: ListStaleReports :many
-- Retention purge: the settled reports older than the cutoff, oldest first.
-- Each one is removed with the same routine as an explicit delete, so both
-- paths leave the same state behind.
SELECT id, project_id FROM reports
WHERE status IN ('completed', 'failed')
  AND COALESCE(completed_at, created_at) < $1
ORDER BY COALESCE(completed_at, created_at), id;

-- name: LockReportForDelete :one
-- Takes the report row for the rest of the transaction, so a scan that moves
-- it to processing cannot slip in between the check and the delete.
SELECT status FROM reports WHERE id = $1 AND project_id = $2 FOR UPDATE;

-- name: LockFindingsByIDs :many
-- Locks the findings a delete is about to settle, in id order, so a
-- concurrent scoped upsert waits instead of writing a severity that the
-- delete then recomputes away.
SELECT id FROM findings
WHERE id = ANY(sqlc.arg(finding_ids)::uuid[])
ORDER BY id
FOR UPDATE;

-- name: ReportScanScopeHash :one
-- The scope a report last observed; a row with no scope is the empty hash.
SELECT COALESCE(scan_scope_hash, '') FROM reports WHERE id = $1 AND project_id = $2;

-- name: ReportDeletionImpact :one
-- What deleting this report would settle, without changing anything. A
-- finding counts as archived when it is open or reopened and no occurrence
-- outside this report (including watcher-only ones) survives the delete.
WITH target AS (
    SELECT id FROM reports
    WHERE id = sqlc.arg(report_id)::uuid AND project_id = sqlc.arg(project_id)::uuid
), touched AS (
    SELECT f.id, f.state
    FROM findings f
    WHERE f.project_id = sqlc.arg(project_id)::uuid
      AND (f.introduced_by_report_id = sqlc.arg(report_id)::uuid
           OR EXISTS (
               SELECT 1 FROM finding_occurrences fo
               WHERE fo.finding_id = f.id AND fo.report_id = sqlc.arg(report_id)::uuid))
)
SELECT
    (SELECT COUNT(*) FROM target)::bigint AS found,
    (SELECT COUNT(*) FROM touched)::bigint AS affected_findings,
    (SELECT COUNT(*) FROM touched t
     WHERE t.state IN ('open', 'reopened')
       AND NOT EXISTS (
           SELECT 1 FROM finding_occurrences fo
           WHERE fo.finding_id = t.id
             AND (fo.report_id IS NULL OR fo.report_id <> sqlc.arg(report_id)::uuid)))::bigint AS archived_findings;

-- name: ListFindingsTouchedByReport :many
-- The findings a report is evidence for, and whether it is the one that
-- introduced them. Read before the delete, which nulls the attribution.
-- A finding with no attribution yet (created by the advisory watcher, or
-- left behind by a partly failed ingest) makes the comparison NULL, which
-- pgx cannot scan into a bool. It is not introduced by this report.
SELECT f.id, COALESCE(f.introduced_by_report_id = sqlc.arg(report_id)::uuid, false)::boolean AS introduced
FROM findings f
WHERE f.project_id = sqlc.arg(project_id)
  AND (f.introduced_by_report_id = sqlc.arg(report_id)::uuid
       OR EXISTS (
           SELECT 1 FROM finding_occurrences fo
           WHERE fo.finding_id = f.id AND fo.report_id = sqlc.arg(report_id)::uuid)
       OR EXISTS (
           SELECT 1 FROM finding_scope_severities s
           WHERE s.finding_id = f.id AND s.report_id = sqlc.arg(report_id)::uuid));

-- name: RepointDuplicateScopeSeverity :exec
UPDATE finding_scope_severities s
SET report_id = winner.id
FROM reports loser, reports winner
WHERE s.report_id = loser.id
  AND loser.id = sqlc.arg(loser_id)::uuid
  AND winner.id = sqlc.arg(winner_id)::uuid
  AND loser.project_id = sqlc.arg(project_id)::uuid
  AND winner.project_id = loser.project_id
  AND winner.status = 'completed'
  AND COALESCE(winner.scan_scope_hash, '') = COALESCE(loser.scan_scope_hash, '');

-- name: ArchiveOrphanedFindings :many
-- Archives the open findings among the given ones that no occurrence supports
-- any more, and records why. Fixed findings keep their state: fixed is still
-- true of them.
WITH orphaned AS (
    SELECT f.id, f.state
    FROM findings f
    WHERE f.id = ANY(sqlc.arg(finding_ids)::uuid[])
      AND f.state IN ('open', 'reopened')
      AND NOT EXISTS (SELECT 1 FROM finding_occurrences fo WHERE fo.finding_id = f.id)
    FOR UPDATE
), archived AS (
    UPDATE findings f
    SET state = 'archived', updated_at = NOW()
    FROM orphaned o
    WHERE f.id = o.id
    RETURNING f.id
), logged AS (
    INSERT INTO finding_events (finding_id, user_id, event_type, old_value, new_value, changes)
    SELECT o.id, sqlc.narg(actor_id)::uuid, 'report_deleted', o.state, 'archived',
           jsonb_build_object('report_id', sqlc.arg(report_id)::text)
    FROM orphaned o
    JOIN archived a ON a.id = o.id
    RETURNING finding_id
)
SELECT finding_id FROM logged;

-- name: RepointIntroducedBy :execrows
-- Gives findings whose introducing report is gone the earliest report that
-- still shows them, so "introduced by this change" stays as true as what
-- remains allows. Findings with no remaining evidence are left alone.
UPDATE findings f
SET introduced_by_report_id = e.report_id, introduced_commit_sha = e.commit_sha
FROM (
    SELECT DISTINCT ON (fo.finding_id) fo.finding_id, r.id AS report_id, r.commit_sha
    FROM finding_occurrences fo
    JOIN reports r ON r.id = fo.report_id
    WHERE fo.finding_id = ANY(sqlc.arg(finding_ids)::uuid[])
    ORDER BY fo.finding_id, r.created_at ASC, r.id ASC
) e
WHERE f.id = e.finding_id
  AND f.introduced_by_report_id IS NULL;

-- name: FindCompletedByReplayKey :one
-- Replay lookup: a completed report for the same project, raw-content hash,
-- commit, and scan scope. A NULL commit_sha or scan_scope_hash compares as
-- the empty string, so ingests that both omit one still find each other.
-- pgx.ErrNoRows means this content is new for this scope at this commit (or
-- only ever failed), so the caller ingests normally.
SELECT id FROM reports
WHERE project_id = $1 AND raw_report_hash = $2
  AND COALESCE(commit_sha, '') = COALESCE($3, '')
  AND COALESCE(scan_scope_hash, '') = COALESCE($4, '')
  AND status = 'completed'
LIMIT 1;

-- name: DeleteReport :exec
-- Removes one report row (duplicate-cleanup path). Occurrences, watcher
-- rows, and inventory cascade; finding attribution nulls; findings
-- themselves survive.
DELETE FROM reports WHERE id = $1 AND project_id = $2;

-- name: ClearRawDataBefore :many
-- The raw retention sweep. It clears the raw_data payload of up to limit settled
-- reports created before the cutoff and returns their ids. The cleared value is
-- JSON null, not SQL NULL: reports stored before raw_data existed (migration
-- 000012) hold SQL NULL, and only a payload the sweep cleared reads as expired.
-- Processing reports are left alone because an ingest may still write them.
UPDATE reports SET raw_data = 'null'::jsonb
WHERE id IN (
    SELECT rr.id FROM reports rr
    WHERE rr.created_at < sqlc.arg(cutoff)
      AND rr.status <> 'processing'
      AND rr.raw_data IS NOT NULL
      AND rr.raw_data <> 'null'::jsonb
    LIMIT sqlc.arg(batch_size)
)
RETURNING id;
