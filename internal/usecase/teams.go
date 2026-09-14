package usecase

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/xMinhx/specht/internal/auth"
	"github.com/xMinhx/specht/internal/port"
)

// ErrTeamConflict is returned when a team name is already taken.
var ErrTeamConflict = errors.New("team conflict")

// ErrTeamNotFound is returned when a team does not exist.
var ErrTeamNotFound = errors.New("team not found")

// TeamResponse is the API representation of a team.
type TeamResponse struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// TeamMemberResponse binds a user to a team.
type TeamMemberResponse struct {
	TeamID    string `json:"team_id"`
	UserID    string `json:"user_id"`
	UserEmail string `json:"user_email,omitempty"`
	Role      string `json:"role"`
}

// ProjectTeamResponse links a team to a project with the conferred role.
type ProjectTeamResponse struct {
	ProjectID string `json:"project_id"`
	TeamID    string `json:"team_id"`
	TeamName  string `json:"team_name"`
	Role      string `json:"role"`
}

// validTeamMemberRoles are the roles a team membership may carry.
var validTeamMemberRoles = map[string]bool{"admin": true, "member": true}

// validLinkRoles are the project roles a team link may confer.
var validLinkRoles = map[string]bool{
	auth.RoleAdmin:  true,
	auth.RoleEditor: true,
	auth.RoleViewer: true,
}

// CreateTeam creates a team; the creator becomes its admin. Any
// authenticated session user may create a team (mirroring project
// creation); API keys never may.
func (u *Usecases) CreateTeam(ctx context.Context, name, description string) (*TeamResponse, error) {
	ident := auth.ContextIdentity(ctx)
	if ident == nil || ident.IsAPIKey {
		return nil, ErrProjectAccessDenied
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("team name is required")
	}
	if len(name) > 64 {
		return nil, fmt.Errorf("team name must not exceed 64 characters")
	}
	if _, err := u.deps.Stores.Teams.GetTeamByName(ctx, name); err == nil {
		return nil, fmt.Errorf("%w: %q", ErrTeamConflict, name)
	} else if !errors.Is(err, port.ErrNotFound) {
		return nil, fmt.Errorf("lookup team: %w", err)
	}
	team, err := u.deps.Stores.Teams.CreateTeam(ctx, name, description)
	if err != nil {
		return nil, fmt.Errorf("create team: %w", err)
	}
	if _, err := u.deps.Stores.Teams.UpsertTeamMember(ctx, team.ID, ident.UserID, auth.RoleAdmin); err != nil {
		return nil, fmt.Errorf("grant creator team admin: %w", err)
	}
	return &TeamResponse{ID: team.ID, Name: team.Name, Description: team.Description}, nil
}

// ListTeams returns every team in name order.
func (u *Usecases) ListTeams(ctx context.Context) ([]TeamResponse, error) {
	teams, err := u.deps.Stores.Teams.ListTeams(ctx)
	if err != nil {
		return nil, fmt.Errorf("list teams: %w", err)
	}
	out := make([]TeamResponse, len(teams))
	for i, t := range teams {
		out[i] = TeamResponse{ID: t.ID, Name: t.Name, Description: t.Description}
	}
	return out, nil
}

// DeleteTeam removes a team; project links cascade. Global admins own
// deletion — team admins manage membership, not the team's existence.
func (u *Usecases) DeleteTeam(ctx context.Context, teamID string) error {
	if _, err := validID(teamID); err != nil {
		return err
	}
	ident := auth.ContextIdentity(ctx)
	if ident == nil || ident.IsAPIKey || ident.Role != auth.RoleAdmin {
		return ErrProjectAccessDenied
	}
	if _, err := u.deps.Stores.Teams.GetTeamByID(ctx, teamID); err != nil {
		return notFoundAsTeam(err)
	}
	if err := u.deps.Stores.Teams.DeleteTeam(ctx, teamID); err != nil {
		return fmt.Errorf("delete team: %w", err)
	}
	return nil
}

// requireTeamAdmin admits global admins and team admins; everyone else
// (including API keys) is denied.
func (u *Usecases) requireTeamAdmin(ctx context.Context, teamID string) error {
	ident := auth.ContextIdentity(ctx)
	if ident == nil || ident.IsAPIKey {
		return ErrProjectAccessDenied
	}
	if ident.Role == auth.RoleAdmin {
		return nil
	}
	if _, err := u.deps.Stores.Teams.GetTeamByID(ctx, teamID); err != nil {
		return notFoundAsTeam(err)
	}
	ok, err := u.deps.Stores.Teams.IsTeamAdmin(ctx, teamID, ident.UserID)
	if err != nil {
		return fmt.Errorf("check team admin: %w", err)
	}
	if !ok {
		return ErrProjectAccessDenied
	}
	return nil
}

// AddTeamMember adds a user to a team. The user must exist (foreign keys
// alone would surface a raw constraint violation); the role validates
// against the team vocabulary.
func (u *Usecases) AddTeamMember(ctx context.Context, teamID, userID, role string) (*TeamMemberResponse, error) {
	if _, err := validID(teamID); err != nil {
		return nil, err
	}
	if _, err := validID(userID); err != nil {
		return nil, err
	}
	if err := u.requireTeamAdmin(ctx, teamID); err != nil {
		return nil, err
	}
	if !validTeamMemberRoles[role] {
		return nil, fmt.Errorf("invalid team role %q: want admin or member", role)
	}
	user, err := u.deps.Stores.Users.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("lookup user: %w", err)
	}
	m, err := u.deps.Stores.Teams.UpsertTeamMember(ctx, teamID, user.ID, role)
	if err != nil {
		return nil, fmt.Errorf("add team member: %w", err)
	}
	return &TeamMemberResponse{TeamID: m.TeamID, UserID: m.UserID, Role: m.Role}, nil
}

// ListTeamMembers returns a team's roster with member emails.
func (u *Usecases) ListTeamMembers(ctx context.Context, teamID string) ([]TeamMemberResponse, error) {
	if _, err := validID(teamID); err != nil {
		return nil, err
	}
	if err := u.requireTeamAdmin(ctx, teamID); err != nil {
		return nil, err
	}
	members, err := u.deps.Stores.Teams.ListTeamMembers(ctx, teamID)
	if err != nil {
		return nil, fmt.Errorf("list team members: %w", err)
	}
	out := make([]TeamMemberResponse, len(members))
	for i, m := range members {
		out[i] = TeamMemberResponse{TeamID: m.TeamID, UserID: m.UserID, UserEmail: m.UserEmail, Role: m.Role}
	}
	return out, nil
}

// RemoveTeamMember removes a user from a team. Removing the last admin is
// allowed (a global admin can always recover the team).
func (u *Usecases) RemoveTeamMember(ctx context.Context, teamID, userID string) error {
	if _, err := validID(teamID); err != nil {
		return err
	}
	if _, err := validID(userID); err != nil {
		return err
	}
	if err := u.requireTeamAdmin(ctx, teamID); err != nil {
		return err
	}
	if err := u.deps.Stores.Teams.RemoveTeamMember(ctx, teamID, userID); err != nil {
		return fmt.Errorf("remove team member: %w", err)
	}
	return nil
}

// LinkProjectTeam confers a project role on every team member. Project
// admins own the assignment (same gate as member management).
func (u *Usecases) LinkProjectTeam(ctx context.Context, projectSlug, teamID, role string) (*ProjectTeamResponse, error) {
	project, err := u.deps.Stores.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return nil, fmt.Errorf("lookup project %q: %w", projectSlug, err)
	}
	if err := u.requireProjectAdmin(ctx, project.ID); err != nil {
		return nil, err
	}
	if _, err := validID(teamID); err != nil {
		return nil, err
	}
	if !validLinkRoles[role] {
		return nil, fmt.Errorf("invalid link role %q: want admin, editor, or viewer", role)
	}
	if _, err := u.deps.Stores.Teams.GetTeamByID(ctx, teamID); err != nil {
		return nil, notFoundAsTeam(err)
	}
	link, err := u.deps.Stores.Teams.LinkProjectTeam(ctx, project.ID, teamID, role)
	if err != nil {
		return nil, fmt.Errorf("link project team: %w", err)
	}
	team, err := u.deps.Stores.Teams.GetTeamByID(ctx, teamID)
	if err != nil {
		return nil, fmt.Errorf("lookup team: %w", err)
	}
	return &ProjectTeamResponse{ProjectID: link.ProjectID, TeamID: link.TeamID, TeamName: team.Name, Role: link.Role}, nil
}

// UnlinkProjectTeam revokes the conferred role. Access granted through the
// link ends with it; direct memberships are untouched.
func (u *Usecases) UnlinkProjectTeam(ctx context.Context, projectSlug, teamID string) error {
	if _, err := validID(teamID); err != nil {
		return err
	}
	project, err := u.deps.Stores.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return fmt.Errorf("lookup project %q: %w", projectSlug, err)
	}
	if err := u.requireProjectAdmin(ctx, project.ID); err != nil {
		return err
	}
	if err := u.deps.Stores.Teams.UnlinkProjectTeam(ctx, project.ID, teamID); err != nil {
		return fmt.Errorf("unlink project team: %w", err)
	}
	return nil
}

// ListProjectTeams returns every team linked to a project.
func (u *Usecases) ListProjectTeams(ctx context.Context, projectSlug string) ([]ProjectTeamResponse, error) {
	project, err := u.deps.Stores.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return nil, fmt.Errorf("lookup project %q: %w", projectSlug, err)
	}
	if err := u.requireProjectAdmin(ctx, project.ID); err != nil {
		return nil, err
	}
	links, err := u.deps.Stores.Teams.ListProjectTeams(ctx, project.ID)
	if err != nil {
		return nil, fmt.Errorf("list project teams: %w", err)
	}
	out := make([]ProjectTeamResponse, len(links))
	for i, l := range links {
		out[i] = ProjectTeamResponse{ProjectID: l.ProjectID, TeamID: l.TeamID, TeamName: l.TeamName, Role: l.Role}
	}
	return out, nil
}

func notFoundAsTeam(err error) error {
	if errors.Is(err, port.ErrNotFound) {
		return ErrTeamNotFound
	}
	return err
}
