package usecase

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xMinhx/specht/internal/auth"
	"github.com/xMinhx/specht/internal/port"
)

func teamHarness() (*Usecases, *mockProjectRepo, *mockTeamRepo, *mockUserRepo) {
	pr, _, _ := makeTestRepos()
	tr := &mockTeamRepo{}
	ur := &mockUserRepo{}
	uc := New(Deps{Stores: &port.Stores{Projects: pr, Teams: tr, Users: ur}})
	return uc, pr, tr, ur
}

func teamMemberCtx() context.Context {
	return auth.ContextWithIdentity(context.Background(), &auth.Identity{
		UserID: "00000000-0000-0000-0000-000000000040",
		Role:   auth.RoleViewer,
	})
}

func TestCreateTeam_CreatorBecomesAdmin(t *testing.T) {
	uc, _, tr, _ := teamHarness()
	tr.getByNameFn = func(ctx context.Context, name string) (port.Team, error) {
		return port.Team{}, port.ErrNotFound
	}
	var created port.Team
	tr.createFn = func(ctx context.Context, name, description string) (port.Team, error) {
		created = port.Team{ID: "team-1", Name: name, Description: description}
		return created, nil
	}
	var memberRole string
	tr.upsertMemberFn = func(ctx context.Context, teamID, userID, role string) (port.TeamMember, error) {
		memberRole = role
		return port.TeamMember{TeamID: teamID, UserID: userID, Role: role}, nil
	}

	out, err := uc.CreateTeam(teamMemberCtx(), "backend", "Backend team")
	require.NoError(t, err)
	assert.Equal(t, "backend", out.Name)
	assert.Equal(t, auth.RoleAdmin, memberRole, "creator administers the team")
}

func TestCreateTeam_ConflictAndValidation(t *testing.T) {
	uc, _, tr, _ := teamHarness()
	tr.getByNameFn = func(ctx context.Context, name string) (port.Team, error) {
		return port.Team{ID: "team-0", Name: name}, nil
	}

	_, err := uc.CreateTeam(teamMemberCtx(), "backend", "")
	assert.ErrorIs(t, err, ErrTeamConflict)

	_, err = uc.CreateTeam(teamMemberCtx(), "   ", "")
	require.Error(t, err)
}

func TestAddTeamMember_TeamAdminGate(t *testing.T) {
	uc, _, tr, ur := teamHarness()
	tr.getByIDFn = func(ctx context.Context, id string) (port.Team, error) {
		return port.Team{ID: "team-1", Name: "backend"}, nil
	}
	tr.isAdminFn = func(ctx context.Context, teamID, userID string) (bool, error) {
		return false, nil
	}

	_, err := uc.AddTeamMember(teamMemberCtx(), "team-1", "user-9", "member")
	assert.ErrorIs(t, err, ErrProjectAccessDenied)

	ur.getByIDFn = func(ctx context.Context, id string) (port.User, error) {
		return makeUser(id), nil
	}
	tr.isAdminFn = func(ctx context.Context, teamID, userID string) (bool, error) {
		return true, nil
	}
	tr.upsertMemberFn = func(ctx context.Context, teamID, userID, role string) (port.TeamMember, error) {
		return port.TeamMember{TeamID: teamID, UserID: userID, Role: role}, nil
	}
	m, err := uc.AddTeamMember(teamMemberCtx(), "team-1", "user-9", "member")
	require.NoError(t, err)
	assert.Equal(t, "member", m.Role)

	_, err = uc.AddTeamMember(teamMemberCtx(), "team-1", "user-9", "superuser")
	require.Error(t, err, "link roles validate against the vocabulary")
}

func TestLinkProjectTeam_ProjectAdminGate(t *testing.T) {
	uc, pr, _, _ := teamHarness()
	project := makeProject(true)
	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return project, nil
	}
	pr.listMembersFn = func(ctx context.Context, projectID string) ([]port.ProjectMember, error) {
		return nil, nil
	}
	pr.effectiveRoleFn = func(ctx context.Context, projectID, userID string) (string, error) {
		return "", port.ErrNotFound
	}

	_, err := uc.LinkProjectTeam(teamMemberCtx(), "my-app", "team-1", "editor")
	assert.ErrorIs(t, err, ErrProjectAccessDenied)
}

func TestLinkProjectTeam_ConfersAccess(t *testing.T) {
	uc, pr, tr, _ := teamHarness()
	project := makeProject(true)
	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return project, nil
	}
	pr.effectiveRoleFn = func(ctx context.Context, projectID, userID string) (string, error) {
		return auth.RoleAdmin, nil
	}
	tr.getByIDFn = func(ctx context.Context, id string) (port.Team, error) {
		return port.Team{ID: "team-1", Name: "backend"}, nil
	}
	tr.linkFn = func(ctx context.Context, projectID, teamID, role string) (port.ProjectTeam, error) {
		return port.ProjectTeam{ProjectID: projectID, TeamID: teamID, Role: role}, nil
	}

	link, err := uc.LinkProjectTeam(adminCtx(), "my-app", "team-1", "editor")
	require.NoError(t, err)
	assert.Equal(t, "editor", link.Role)
}

func TestCheckAccess_ViaTeamMembership(t *testing.T) {
	pr, _, fr := makeTestRepos()
	pr.isMemberEffectiveFn = func(ctx context.Context, projectID, userID string) (bool, error) {
		return true, nil
	}
	f := makeFinding(1)
	fr.getByIDFn = func(ctx context.Context, id string) (port.Finding, error) {
		return f, nil
	}
	uc := New(Deps{Stores: &port.Stores{Projects: pr, Findings: fr}})

	err := uc.checkFindingProjectIDAccess(teamMemberCtx(), f.ProjectID)
	assert.NoError(t, err, "team-conferred membership grants access")
}

func TestRequireProjectAdmin_ViaTeamRole(t *testing.T) {
	pr, _, _ := makeTestRepos()
	pr.effectiveRoleFn = func(ctx context.Context, projectID, userID string) (string, error) {
		return auth.RoleAdmin, nil
	}
	uc := New(Deps{Stores: &port.Stores{Projects: pr}})

	assert.NoError(t, uc.requireProjectAdmin(teamMemberCtx(), makeProject(true).ID))
}
