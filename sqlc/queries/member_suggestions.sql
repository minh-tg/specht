-- name: SuggestMembers :many
-- Accounts a project manager may want to add to a project, matched by a
-- prefix of the email or of any word in the display name. The prefix arrives
-- lowercased with LIKE wildcards escaped; emails are stored lowercased
-- (migration 000037). Disabled accounts, the seeded system account and people
-- who are already direct members are left out. There is no index for this:
-- a sequential scan of the users table is fine at directory scale, and the
-- caller caps the result at a handful of rows.
SELECT * FROM users
WHERE disabled_at IS NULL
  AND email <> 'system@specht.local'
  AND (
    email LIKE (sqlc.arg(prefix)::text || '%') ESCAPE E'\\'
    OR (' ' || lower(coalesce(display_name, ''))) LIKE ('% ' || sqlc.arg(prefix)::text || '%') ESCAPE E'\\'
  )
  AND NOT EXISTS (
    SELECT 1 FROM project_members pm
    WHERE pm.project_id = sqlc.arg(project_id) AND pm.user_id = users.id
  )
ORDER BY email ASC, id ASC
LIMIT sqlc.arg(result_limit);
