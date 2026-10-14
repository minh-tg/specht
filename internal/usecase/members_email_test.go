package usecase

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
)

const (
	emailTestCaller = "00000000-0000-4000-8000-000000000007"
	emailTestUser   = "00000000-0000-4000-8000-000000000012"
	emailTestTeam   = "11111111-1111-1111-1111-111111111111"
)

func TestAddProjectMemberByEmail_ResolvesTheAddressAfterTheAccessCheck(t *testing.T) {
	pr := &mockProjectRepo{}
	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return memberTestProject(), nil
	}
	pr.listMembersFn = func(ctx context.Context, projectID string) ([]port.ProjectMember, error) {
		return []port.ProjectMember{{ProjectID: projectID, UserID: emailTestCaller, Role: auth.RoleManager}}, nil
	}
	var upsertedUser string
	pr.upsertMemberFn = func(ctx context.Context, projectID, userID, role string) (port.ProjectMember, error) {
		upsertedUser = userID
		return port.ProjectMember{ProjectID: projectID, UserID: userID, Role: role}, nil
	}
	var lookedUp string
	ur := &mockUserRepo{getByEmailFn: func(ctx context.Context, email string) (port.User, error) {
		lookedUp = email
		return makeUser(emailTestUser), nil
	}}
	uc := New(Deps{Stores: &port.Stores{Projects: pr, Users: ur}})

	m, err := uc.AddProjectMemberByEmail(sessionCtx(emailTestCaller, auth.RoleMember), "my-app", "  Ada@Acme.Example ", auth.RoleMember)
	require.NoError(t, err)
	assert.Equal(t, "ada@acme.example", lookedUp, "the address is trimmed and lowercased before the lookup")
	assert.Equal(t, emailTestUser, upsertedUser)
	assert.Equal(t, emailTestUser, m.UserID)
}

func TestAddProjectMemberByEmail_UnknownAddressIsTheSameErrorAsUnknownUser(t *testing.T) {
	pr := &mockProjectRepo{}
	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return memberTestProject(), nil
	}
	ur := &mockUserRepo{getByEmailFn: func(ctx context.Context, email string) (port.User, error) {
		return port.User{}, port.ErrNotFound
	}}
	uc := New(Deps{Stores: &port.Stores{Projects: pr, Users: ur}})

	_, err := uc.AddProjectMemberByEmail(sessionCtx(emailTestCaller, auth.RoleAdmin), "my-app", "nobody@acme.example", auth.RoleMember)
	assert.ErrorIs(t, err, ErrMemberUserNotFound)
}

func TestAddProjectMemberByEmail_CallerWithoutAccessNeverTriggersALookup(t *testing.T) {
	pr := &mockProjectRepo{}
	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return memberTestProject(), nil
	}
	pr.listMembersFn = func(ctx context.Context, projectID string) ([]port.ProjectMember, error) {
		return []port.ProjectMember{{ProjectID: projectID, UserID: emailTestCaller, Role: auth.RoleViewer}}, nil
	}
	ur := &mockUserRepo{getByEmailFn: func(ctx context.Context, email string) (port.User, error) {
		t.Fatal("a caller who may not add members must not learn whether an address has an account")
		return port.User{}, nil
	}}
	uc := New(Deps{Stores: &port.Stores{Projects: pr, Users: ur}})

	_, err := uc.AddProjectMemberByEmail(sessionCtx(emailTestCaller, auth.RoleMember), "my-app", "ada@acme.example", auth.RoleMember)
	assert.ErrorIs(t, err, ErrProjectAccessDenied)
}

func TestAddProjectMemberByEmail_RejectsAMalformedAddress(t *testing.T) {
	uc := New(Deps{Stores: &port.Stores{Projects: &mockProjectRepo{}, Users: &mockUserRepo{}}})
	for _, email := range []string{"", "   ", "not-an-address", "Ada <ada@acme.example>"} {
		_, err := uc.AddProjectMemberByEmail(sessionCtx(emailTestCaller, auth.RoleAdmin), "my-app", email, auth.RoleMember)
		assert.ErrorIs(t, err, ErrInvalidMemberEmail, "email %q", email)
	}
}

func TestAddTeamMemberByEmail_ResolvesAfterTheTeamAdminGate(t *testing.T) {
	uc, _, tr, ur := teamHarness()
	tr.getByIDFn = func(ctx context.Context, id string) (port.Team, error) {
		return port.Team{ID: emailTestTeam, Name: "backend"}, nil
	}
	tr.isAdminFn = func(ctx context.Context, teamID, userID string) (bool, error) {
		return false, nil
	}
	ur.getByEmailFn = func(ctx context.Context, email string) (port.User, error) {
		t.Fatal("a non-admin of the team must not trigger an address lookup")
		return port.User{}, nil
	}
	_, err := uc.AddTeamMemberByEmail(teamMemberCtx(), emailTestTeam, "ada@acme.example", "member")
	assert.ErrorIs(t, err, ErrProjectAccessDenied)

	tr.isAdminFn = func(ctx context.Context, teamID, userID string) (bool, error) {
		return true, nil
	}
	var lookedUp string
	ur.getByEmailFn = func(ctx context.Context, email string) (port.User, error) {
		lookedUp = email
		return makeUser(emailTestUser), nil
	}
	var addedUser string
	tr.upsertMemberFn = func(ctx context.Context, teamID, userID, role string) (port.TeamMember, error) {
		addedUser = userID
		return port.TeamMember{TeamID: teamID, UserID: userID, Role: role}, nil
	}
	m, err := uc.AddTeamMemberByEmail(teamMemberCtx(), emailTestTeam, "Ada@Acme.Example", "member")
	require.NoError(t, err)
	assert.Equal(t, "ada@acme.example", lookedUp)
	assert.Equal(t, emailTestUser, addedUser)
	assert.Equal(t, emailTestUser, m.UserID)
}

func TestAddTeamMemberByEmail_UnknownAddressIsTyped(t *testing.T) {
	uc, _, tr, ur := teamHarness()
	tr.getByIDFn = func(ctx context.Context, id string) (port.Team, error) {
		return port.Team{ID: emailTestTeam, Name: "backend"}, nil
	}
	tr.isAdminFn = func(ctx context.Context, teamID, userID string) (bool, error) {
		return true, nil
	}
	ur.getByEmailFn = func(ctx context.Context, email string) (port.User, error) {
		return port.User{}, port.ErrNotFound
	}
	_, err := uc.AddTeamMemberByEmail(teamMemberCtx(), emailTestTeam, "nobody@acme.example", "member")
	assert.ErrorIs(t, err, ErrMemberUserNotFound)
}

func TestAddProjectMemberByEmail_NeverAddsTheSystemAccount(t *testing.T) {
	pr := &mockProjectRepo{}
	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return memberTestProject(), nil
	}
	pr.upsertMemberFn = func(ctx context.Context, projectID, userID, role string) (port.ProjectMember, error) {
		t.Fatal("the system account must not become a member")
		return port.ProjectMember{}, nil
	}
	ur := &mockUserRepo{getByEmailFn: func(ctx context.Context, email string) (port.User, error) {
		return port.User{ID: emailTestUser, Email: SystemAccountEmail, Role: auth.RoleMember}, nil
	}}
	uc := New(Deps{Stores: &port.Stores{Projects: pr, Users: ur}})

	_, err := uc.AddProjectMemberByEmail(sessionCtx(emailTestCaller, auth.RoleAdmin), "my-app", SystemAccountEmail, auth.RoleMember)
	assert.ErrorIs(t, err, ErrMemberUserNotFound, "it answers like any address with no account")
}

func TestAddTeamMemberByEmail_NeverAddsTheSystemAccount(t *testing.T) {
	uc, _, tr, ur := teamHarness()
	tr.getByIDFn = func(ctx context.Context, id string) (port.Team, error) {
		return port.Team{ID: emailTestTeam, Name: "backend"}, nil
	}
	tr.isAdminFn = func(ctx context.Context, teamID, userID string) (bool, error) { return true, nil }
	tr.upsertMemberFn = func(ctx context.Context, teamID, userID, role string) (port.TeamMember, error) {
		t.Fatal("the system account must not join a team")
		return port.TeamMember{}, nil
	}
	ur.getByEmailFn = func(ctx context.Context, email string) (port.User, error) {
		return port.User{ID: emailTestUser, Email: SystemAccountEmail}, nil
	}
	_, err := uc.AddTeamMemberByEmail(teamMemberCtx(), emailTestTeam, SystemAccountEmail, "member")
	assert.ErrorIs(t, err, ErrMemberUserNotFound)
}
