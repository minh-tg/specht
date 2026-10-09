package usecase

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
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

// CreateTeam creates a team in the central company directory; the creator becomes its admin.
// Only global administrators may create teams; API keys never may.
func (u *Usecases) CreateTeam(ctx context.Context, name, description string) (*TeamResponse, error) {
	ident := auth.ContextIdentity(ctx)
	if ident == nil || ident.IsAPIKey || ident.Role != auth.RoleAdmin {
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

// ListTeams returns every team in name order to callers who belong to the
// organisation: global admins and users with access to at least one project,
// directly or through a team. Self-registered accounts with no access get an
// empty directory instead of the company's team names, and API keys, which
// authenticate a project and not a person, are refused.
func (u *Usecases) ListTeams(ctx context.Context) ([]TeamResponse, error) {
	ident := auth.ContextIdentity(ctx)
	if ident == nil || ident.IsAPIKey {
		return nil, ErrProjectAccessDenied
	}
	if ident.Role != auth.RoleAdmin {
		accessible, err := u.deps.Stores.Projects.ListAccessibleProjectIDs(ctx, ident.UserID)
		if err != nil {
			return nil, fmt.Errorf("check directory access: %w", err)
		}
		if len(accessible) == 0 {
			return []TeamResponse{}, nil
		}
	}
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

// requireDelegationCeiling keeps team administration from outranking project
// administration. Adding someone to a team hands them every role the team is
// linked at, so a non-admin caller must hold each elevated role (above
// member) through a direct project membership. The team's own link cannot
// vouch for the caller: that would let any team admin delegate whatever the
// project admins gave the team. Global admins are exempt.
func (u *Usecases) requireDelegationCeiling(ctx context.Context, teamID string) error {
	ident := auth.ContextIdentity(ctx)
	if ident == nil || ident.IsAPIKey {
		return ErrProjectAccessDenied
	}
	if ident.Role == auth.RoleAdmin {
		return nil
	}
	links, err := u.deps.Stores.Teams.ListTeamProjectLinks(ctx, teamID)
	if err != nil {
		return fmt.Errorf("list team project links: %w", err)
	}
	for _, l := range links {
		linkRole := normalizeMemberRole(l.Role)
		if auth.RoleRank(linkRole) <= auth.RoleRank(auth.RoleMember) {
			continue
		}
		direct, err := u.deps.Stores.Projects.GetMember(ctx, l.ProjectID, ident.UserID)
		switch {
		case errors.Is(err, port.ErrNotFound):
			return ErrProjectAccessDenied
		case err != nil:
			return fmt.Errorf("resolve direct project role: %w", err)
		}
		if auth.RoleRank(normalizeMemberRole(direct.Role)) < auth.RoleRank(linkRole) {
			return ErrProjectAccessDenied
		}
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
		return nil, fmt.Errorf("%w %q: want admin or member", ErrInvalidMemberRole, role)
	}
	if err := u.requireDelegationCeiling(ctx, teamID); err != nil {
		return nil, err
	}
	user, err := u.deps.Stores.Users.GetByID(ctx, userID)
	if err != nil {
		if errors.Is(err, port.ErrNotFound) {
			return nil, ErrMemberUserNotFound
		}
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
// managers and admins may link teams, with a delegation ceiling that limits
// the conferred role to the caller's own rank. Relinking is an upsert, so
// non-admins may not rewrite an existing link at or above their own rank.
func (u *Usecases) LinkProjectTeam(ctx context.Context, projectSlug, teamID, role string) (*ProjectTeamResponse, error) {
	project, err := u.deps.Stores.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return nil, fmt.Errorf(errLookupProjectFormat, projectSlug, err)
	}
	callerRole, err := u.callerProjectRole(ctx, project.ID)
	if err != nil {
		return nil, err
	}
	if auth.RoleRank(callerRole) < auth.RoleRank(auth.RoleManager) {
		return nil, ErrProjectAccessDenied
	}
	if _, err := validID(teamID); err != nil {
		return nil, err
	}
	role = normalizeMemberRole(role)
	if !memberRoles[role] {
		return nil, fmt.Errorf("invalid link role %q: want admin, manager, or member", role)
	}
	// Delegation ceiling: cannot link a team with a role higher than caller's rank.
	if auth.RoleRank(role) > auth.RoleRank(callerRole) {
		return nil, ErrProjectAccessDenied
	}
	if err := u.checkExistingLinkPermission(ctx, project.ID, teamID, callerRole); err != nil {
		return nil, err
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
	return &ProjectTeamResponse{ProjectID: link.ProjectID, TeamID: link.TeamID, TeamName: team.Name, Role: normalizeMemberRole(link.Role)}, nil
}

// checkExistingLinkPermission ensures non-admin callers cannot rewrite or
// remove a team link whose role is at or above their own.
func (u *Usecases) checkExistingLinkPermission(ctx context.Context, projectID, teamID, callerRole string) error {
	if auth.RoleRank(callerRole) >= auth.RoleRank(auth.RoleAdmin) {
		return nil
	}
	links, err := u.deps.Stores.Teams.ListProjectTeams(ctx, projectID)
	if err != nil {
		return fmt.Errorf("list project teams: %w", err)
	}
	for _, l := range links {
		if l.TeamID == teamID && auth.RoleRank(normalizeMemberRole(l.Role)) >= auth.RoleRank(callerRole) {
			return ErrProjectAccessDenied
		}
	}
	return nil
}

// UnlinkProjectTeam revokes the conferred role. Project managers may unlink
// only member-level teams; unlinking manager or admin teams requires project
// admin authority.
func (u *Usecases) UnlinkProjectTeam(ctx context.Context, projectSlug, teamID string) error {
	if _, err := validID(teamID); err != nil {
		return err
	}
	project, err := u.deps.Stores.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return fmt.Errorf(errLookupProjectFormat, projectSlug, err)
	}
	callerRole, err := u.callerProjectRole(ctx, project.ID)
	if err != nil {
		return err
	}
	if auth.RoleRank(callerRole) < auth.RoleRank(auth.RoleManager) {
		return ErrProjectAccessDenied
	}
	if err := u.checkExistingLinkPermission(ctx, project.ID, teamID, callerRole); err != nil {
		return err
	}
	if err := u.deps.Stores.Teams.UnlinkProjectTeam(ctx, project.ID, teamID); err != nil {
		return fmt.Errorf("unlink project team: %w", err)
	}
	return nil
}

// ListProjectTeams returns every team linked to a project.
// Accessible to project members, managers, and admins.
func (u *Usecases) ListProjectTeams(ctx context.Context, projectSlug string) ([]ProjectTeamResponse, error) {
	project, err := u.deps.Stores.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return nil, fmt.Errorf(errLookupProjectFormat, projectSlug, err)
	}
	if err := u.requireProjectMember(ctx, project.ID); err != nil {
		return nil, err
	}
	links, err := u.deps.Stores.Teams.ListProjectTeams(ctx, project.ID)
	if err != nil {
		return nil, fmt.Errorf("list project teams: %w", err)
	}
	out := make([]ProjectTeamResponse, len(links))
	for i, l := range links {
		out[i] = ProjectTeamResponse{ProjectID: l.ProjectID, TeamID: l.TeamID, TeamName: l.TeamName, Role: normalizeMemberRole(l.Role)}
	}
	return out, nil
}

func notFoundAsTeam(err error) error {
	if errors.Is(err, port.ErrNotFound) {
		return ErrTeamNotFound
	}
	return err
}
