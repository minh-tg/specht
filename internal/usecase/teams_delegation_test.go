package usecase

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
)

const (
	delegTeamID    = "11111111-1111-1111-1111-111111111111"
	delegNewUserID = "22222222-2222-2222-2222-222222222222"
	delegProjectA  = "33333333-3333-3333-3333-333333333333"
	delegProjectB  = "44444444-4444-4444-4444-444444444444"
)

// delegationHarness is a team whose admin (the session caller) adds members,
// with the team linked to the given projects and the caller's direct project
// roles taken from direct (project id -> role; absent means no direct row).
func delegationHarness(links []port.ProjectTeam, direct map[string]string) (*Usecases, *int) {
	uc, pr, tr, ur := teamHarness()
	upserts := new(int)
	tr.getByIDFn = func(context.Context, string) (port.Team, error) {
		return port.Team{ID: delegTeamID, Name: "backend"}, nil
	}
	tr.isAdminFn = func(context.Context, string, string) (bool, error) { return true, nil }
	tr.teamLinksFn = func(context.Context, string) ([]port.ProjectTeam, error) { return links, nil }
	tr.upsertMemberFn = func(_ context.Context, teamID, userID, role string) (port.TeamMember, error) {
		*upserts++
		return port.TeamMember{TeamID: teamID, UserID: userID, Role: role}, nil
	}
	ur.getByIDFn = func(_ context.Context, id string) (port.User, error) { return makeUser(id), nil }
	pr.getMemberFn = func(_ context.Context, projectID, _ string) (port.ProjectMember, error) {
		role, ok := direct[projectID]
		if !ok {
			return port.ProjectMember{}, port.ErrNotFound
		}
		return port.ProjectMember{ProjectID: projectID, Role: role}, nil
	}
	return uc, upserts
}

func link(projectID, role string) port.ProjectTeam {
	return port.ProjectTeam{ProjectID: projectID, TeamID: delegTeamID, Role: role}
}

func TestAddTeamMember_CannotGrantAProjectRoleTheCallerLacksDirectly(t *testing.T) {
	tests := []struct {
		name    string
		links   []port.ProjectTeam
		direct  map[string]string
		allowed bool
	}{
		{"no project links", nil, nil, true},
		{"link at member needs no project rank", []port.ProjectTeam{link(delegProjectA, "member")}, nil, true},
		{"link at manager, caller has no direct role", []port.ProjectTeam{link(delegProjectA, "manager")}, nil, false},
		{"link at manager, caller only a direct member", []port.ProjectTeam{link(delegProjectA, "manager")}, map[string]string{delegProjectA: "member"}, false},
		{"link at manager, caller direct manager", []port.ProjectTeam{link(delegProjectA, "manager")}, map[string]string{delegProjectA: "manager"}, true},
		{"link at admin, caller direct manager", []port.ProjectTeam{link(delegProjectA, "admin")}, map[string]string{delegProjectA: "manager"}, false},
		{"link at admin, caller direct admin", []port.ProjectTeam{link(delegProjectA, "admin")}, map[string]string{delegProjectA: "admin"}, true},
		{"legacy editor link counts as manager", []port.ProjectTeam{link(delegProjectA, "editor")}, map[string]string{delegProjectA: "member"}, false},
		{
			"every elevated link must be covered",
			[]port.ProjectTeam{link(delegProjectA, "manager"), link(delegProjectB, "admin")},
			map[string]string{delegProjectA: "admin", delegProjectB: "manager"},
			false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			uc, upserts := delegationHarness(tc.links, tc.direct)

			_, err := uc.AddTeamMember(teamMemberCtx(), delegTeamID, delegNewUserID, "member")

			if tc.allowed {
				require.NoError(t, err)
				assert.Equal(t, 1, *upserts)
				return
			}
			assert.ErrorIs(t, err, ErrProjectAccessDenied)
			assert.Zero(t, *upserts, "a refused delegation must not add the member")
		})
	}
}

func TestAddTeamMember_GlobalAdminIsNotLimitedByProjectLinks(t *testing.T) {
	uc, upserts := delegationHarness([]port.ProjectTeam{link(delegProjectA, "admin")}, nil)
	ctx := auth.ContextWithIdentity(context.Background(), &auth.Identity{
		UserID: "00000000-0000-0000-0000-000000000001",
		Role:   auth.RoleAdmin,
	})

	_, err := uc.AddTeamMember(ctx, delegTeamID, delegNewUserID, "member")

	require.NoError(t, err)
	assert.Equal(t, 1, *upserts)
}

func TestAddTeamMember_FailsClosedWhenTheDelegationCheckErrors(t *testing.T) {
	t.Run("link listing", func(t *testing.T) {
		uc, upserts := delegationHarness(nil, nil)
		uc.deps.Stores.Teams.(*mockTeamRepo).teamLinksFn = func(context.Context, string) ([]port.ProjectTeam, error) {
			return nil, errors.New("db down")
		}

		_, err := uc.AddTeamMember(teamMemberCtx(), delegTeamID, delegNewUserID, "member")

		require.Error(t, err)
		assert.NotErrorIs(t, err, ErrProjectAccessDenied, "an infrastructure fault is not a denial")
		assert.Zero(t, *upserts)
	})
	t.Run("direct role lookup", func(t *testing.T) {
		uc, upserts := delegationHarness([]port.ProjectTeam{link(delegProjectA, "manager")}, nil)
		uc.deps.Stores.Projects.(*mockProjectRepo).getMemberFn = func(context.Context, string, string) (port.ProjectMember, error) {
			return port.ProjectMember{}, errors.New("db down")
		}

		_, err := uc.AddTeamMember(teamMemberCtx(), delegTeamID, delegNewUserID, "member")

		require.Error(t, err)
		assert.NotErrorIs(t, err, ErrProjectAccessDenied)
		assert.Zero(t, *upserts)
	})
}
