-- name: CreateTeam :one
INSERT INTO teams (name, description)
VALUES ($1, $2)
RETURNING *;

-- name: GetTeamByID :one
SELECT * FROM teams WHERE id = $1;

-- name: GetTeamByName :one
SELECT * FROM teams WHERE name = $1;

-- name: ListTeams :many
SELECT * FROM teams
ORDER BY name ASC;

-- name: DeleteTeam :exec
DELETE FROM teams WHERE id = $1;

-- name: UpsertTeamMember :one
INSERT INTO team_members (team_id, user_id, role)
VALUES ($1, $2, $3)
ON CONFLICT (team_id, user_id) DO UPDATE SET role = EXCLUDED.role
RETURNING *;

-- name: ListTeamMembers :many
SELECT tm.team_id, tm.user_id, tm.role, tm.created_at, u.email
FROM team_members tm
JOIN users u ON u.id = tm.user_id
WHERE tm.team_id = $1
ORDER BY u.email ASC;

-- name: RemoveTeamMember :exec
DELETE FROM team_members WHERE team_id = $1 AND user_id = $2;

-- name: IsTeamMember :one
SELECT EXISTS (
    SELECT 1 FROM team_members WHERE team_id = $1 AND user_id = $2
) AS is_member;

-- name: IsTeamAdmin :one
SELECT EXISTS (
    SELECT 1 FROM team_members WHERE team_id = $1 AND user_id = $2 AND role = 'admin'
) AS is_admin;

-- name: LinkProjectTeam :one
INSERT INTO project_teams (project_id, team_id, role)
VALUES ($1, $2, $3)
ON CONFLICT (project_id, team_id) DO UPDATE SET role = EXCLUDED.role
RETURNING *;

-- name: UnlinkProjectTeam :exec
DELETE FROM project_teams WHERE project_id = $1 AND team_id = $2;

-- name: ListProjectTeams :many
SELECT pt.project_id, pt.team_id, pt.role, pt.created_at, t.name AS team_name
FROM project_teams pt
JOIN teams t ON t.id = pt.team_id
WHERE pt.project_id = $1
ORDER BY t.name ASC;

-- name: ListTeamProjectLinks :many
SELECT pt.project_id, pt.team_id, pt.role, pt.created_at, t.name AS team_name
FROM project_teams pt
JOIN teams t ON t.id = pt.team_id
WHERE pt.team_id = $1
ORDER BY pt.project_id ASC;

-- name: IsProjectMemberEffective :one
-- Effective membership: a direct project_members row OR membership in any
-- team linked to the project. The single choke point for session-user
-- project access.
SELECT EXISTS (
    SELECT 1 FROM project_members pm WHERE pm.project_id = $1 AND pm.user_id = $2
) OR EXISTS (
    SELECT 1 FROM project_teams pt
    JOIN team_members tm ON tm.team_id = pt.team_id
    WHERE pt.project_id = $1 AND tm.user_id = $2
) AS is_member;

-- name: ListAccessibleProjectIDs :many
-- Every project a user reaches directly or through a team, for the
-- batched list path (replaces per-project checks).
SELECT pm.project_id FROM project_members pm WHERE pm.user_id = $1
UNION
SELECT pt.project_id FROM project_teams pt
JOIN team_members tm ON tm.team_id = pt.team_id
WHERE tm.user_id = $1;

-- name: EffectiveProjectRole :one
-- The strongest role a user holds on a project across direct membership
-- and team links (admin > manager > member). pgx.ErrNoRows means no access
-- at all — callers treat it as denial, never as a default role.
SELECT ranked.role FROM (
    SELECT role,
        CASE role WHEN 'admin' THEN 3 WHEN 'manager' THEN 2 WHEN 'editor' THEN 2 ELSE 1 END AS rank
    FROM (
        SELECT pm.role FROM project_members pm WHERE pm.project_id = $1 AND pm.user_id = $2
        UNION ALL
        SELECT pt.role FROM project_teams pt
        JOIN team_members tm ON tm.team_id = pt.team_id
        WHERE pt.project_id = $1 AND tm.user_id = $2
    ) roles
) ranked
ORDER BY ranked.rank DESC
LIMIT 1;
