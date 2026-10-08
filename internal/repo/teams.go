package repo

import (
	"context"

	"github.com/minh-tg/specht/internal/db/sqlc"
	"github.com/minh-tg/specht/internal/port"
)

// pgTeamPort persists teams, memberships, and project links directly over
// sqlc.
type pgTeamPort struct{ q *sqlc.Queries }

func teamRowToPort(t sqlc.Team) port.Team {
	return port.Team{
		ID:          toUUID(t.ID),
		Name:        t.Name,
		Description: t.Description,
		CreatedAt:   t.CreatedAt.Time,
		UpdatedAt:   t.UpdatedAt.Time,
	}
}

func (r *pgTeamPort) CreateTeam(ctx context.Context, name, description string) (port.Team, error) {
	row, err := r.q.CreateTeam(ctx, sqlc.CreateTeamParams{
		Name:        name,
		Description: description,
	})
	if err != nil {
		return port.Team{}, mappingErr(err)
	}
	return teamRowToPort(row), nil
}

func (r *pgTeamPort) GetTeamByID(ctx context.Context, id string) (port.Team, error) {
	tid, err := parseID(id)
	if err != nil {
		return port.Team{}, err
	}
	row, err := r.q.GetTeamByID(ctx, tid)
	if err != nil {
		return port.Team{}, mappingErr(err)
	}
	return teamRowToPort(row), nil
}

func (r *pgTeamPort) GetTeamByName(ctx context.Context, name string) (port.Team, error) {
	row, err := r.q.GetTeamByName(ctx, name)
	if err != nil {
		return port.Team{}, mappingErr(err)
	}
	return teamRowToPort(row), nil
}

func (r *pgTeamPort) ListTeams(ctx context.Context) ([]port.Team, error) {
	rows, err := r.q.ListTeams(ctx)
	if err != nil {
		return nil, mappingErr(err)
	}
	out := make([]port.Team, len(rows))
	for i, row := range rows {
		out[i] = teamRowToPort(row)
	}
	return out, nil
}

func (r *pgTeamPort) DeleteTeam(ctx context.Context, id string) error {
	tid, err := parseID(id)
	if err != nil {
		return err
	}
	return mappingErr(r.q.DeleteTeam(ctx, tid))
}

func (r *pgTeamPort) UpsertTeamMember(ctx context.Context, teamID, userID, role string) (port.TeamMember, error) {
	tid, err := parseID(teamID)
	if err != nil {
		return port.TeamMember{}, err
	}
	uid, err := parseID(userID)
	if err != nil {
		return port.TeamMember{}, err
	}
	row, err := r.q.UpsertTeamMember(ctx, sqlc.UpsertTeamMemberParams{
		TeamID: tid,
		UserID: uid,
		Role:   role,
	})
	if err != nil {
		return port.TeamMember{}, mappingErr(err)
	}
	return teamMemberRowToPort(row), nil
}

func teamMemberRowToPort(row sqlc.TeamMember) port.TeamMember {
	return port.TeamMember{
		TeamID:    toUUID(row.TeamID),
		UserID:    toUUID(row.UserID),
		Role:      row.Role,
		CreatedAt: row.CreatedAt.Time,
	}
}

func (r *pgTeamPort) ListTeamMembers(ctx context.Context, teamID string) ([]port.TeamMember, error) {
	tid, err := parseID(teamID)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListTeamMembers(ctx, tid)
	if err != nil {
		return nil, mappingErr(err)
	}
	out := make([]port.TeamMember, len(rows))
	for i, row := range rows {
		out[i] = port.TeamMember{
			TeamID:    toUUID(row.TeamID),
			UserID:    toUUID(row.UserID),
			UserEmail: row.Email,
			Role:      row.Role,
			CreatedAt: row.CreatedAt.Time,
		}
	}
	return out, nil
}

func (r *pgTeamPort) RemoveTeamMember(ctx context.Context, teamID, userID string) error {
	tid, err := parseID(teamID)
	if err != nil {
		return err
	}
	uid, err := parseID(userID)
	if err != nil {
		return err
	}
	return mappingErr(r.q.RemoveTeamMember(ctx, sqlc.RemoveTeamMemberParams{
		TeamID: tid,
		UserID: uid,
	}))
}

func (r *pgTeamPort) IsTeamMember(ctx context.Context, teamID, userID string) (bool, error) {
	tid, err := parseID(teamID)
	if err != nil {
		return false, err
	}
	uid, err := parseID(userID)
	if err != nil {
		return false, err
	}
	return r.q.IsTeamMember(ctx, sqlc.IsTeamMemberParams{
		TeamID: tid,
		UserID: uid,
	})
}

func (r *pgTeamPort) IsTeamAdmin(ctx context.Context, teamID, userID string) (bool, error) {
	tid, err := parseID(teamID)
	if err != nil {
		return false, err
	}
	uid, err := parseID(userID)
	if err != nil {
		return false, err
	}
	return r.q.IsTeamAdmin(ctx, sqlc.IsTeamAdminParams{
		TeamID: tid,
		UserID: uid,
	})
}

func (r *pgTeamPort) LinkProjectTeam(ctx context.Context, projectID, teamID, role string) (port.ProjectTeam, error) {
	pid, err := parseID(projectID)
	if err != nil {
		return port.ProjectTeam{}, err
	}
	tid, err := parseID(teamID)
	if err != nil {
		return port.ProjectTeam{}, err
	}
	row, err := r.q.LinkProjectTeam(ctx, sqlc.LinkProjectTeamParams{
		ProjectID: pid,
		TeamID:    tid,
		Role:      role,
	})
	if err != nil {
		return port.ProjectTeam{}, mappingErr(err)
	}
	return port.ProjectTeam{
		ProjectID: toUUID(row.ProjectID),
		TeamID:    toUUID(row.TeamID),
		Role:      row.Role,
		CreatedAt: row.CreatedAt.Time,
	}, nil
}

func (r *pgTeamPort) UnlinkProjectTeam(ctx context.Context, projectID, teamID string) error {
	pid, err := parseID(projectID)
	if err != nil {
		return err
	}
	tid, err := parseID(teamID)
	if err != nil {
		return err
	}
	return mappingErr(r.q.UnlinkProjectTeam(ctx, sqlc.UnlinkProjectTeamParams{
		ProjectID: pid,
		TeamID:    tid,
	}))
}

func (r *pgTeamPort) ListProjectTeams(ctx context.Context, projectID string) ([]port.ProjectTeam, error) {
	pid, err := parseID(projectID)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListProjectTeams(ctx, pid)
	if err != nil {
		return nil, mappingErr(err)
	}
	out := make([]port.ProjectTeam, len(rows))
	for i, row := range rows {
		out[i] = port.ProjectTeam{
			ProjectID: toUUID(row.ProjectID),
			TeamID:    toUUID(row.TeamID),
			TeamName:  row.TeamName,
			Role:      row.Role,
			CreatedAt: row.CreatedAt.Time,
		}
	}
	return out, nil
}

func (r *pgTeamPort) ListTeamProjectLinks(ctx context.Context, teamID string) ([]port.ProjectTeam, error) {
	tid, err := parseID(teamID)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListTeamProjectLinks(ctx, tid)
	if err != nil {
		return nil, mappingErr(err)
	}
	out := make([]port.ProjectTeam, len(rows))
	for i, row := range rows {
		out[i] = port.ProjectTeam{
			ProjectID: toUUID(row.ProjectID),
			TeamID:    toUUID(row.TeamID),
			TeamName:  row.TeamName,
			Role:      row.Role,
			CreatedAt: row.CreatedAt.Time,
		}
	}
	return out, nil
}
