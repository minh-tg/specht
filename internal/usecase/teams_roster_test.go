package usecase

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
)

const rosterTeamID = "11111111-1111-1111-1111-111111111111"

func rosterHarness() (*Usecases, *mockTeamRepo) {
	uc, _, tr, _ := teamHarness()
	tr.getByIDFn = func(ctx context.Context, id string) (port.Team, error) {
		return port.Team{ID: id, Name: "backend"}, nil
	}
	tr.isAdminFn = func(ctx context.Context, teamID, userID string) (bool, error) {
		return false, nil
	}
	tr.listMembersFn = func(ctx context.Context, teamID string) ([]port.TeamMember, error) {
		return []port.TeamMember{
			{TeamID: teamID, UserID: "u1", UserEmail: "ada@acme.example", DisplayName: "Ada Okafor", Role: "admin"},
			{TeamID: teamID, UserID: "u2", UserEmail: "bo@acme.example", Role: "member"},
		}, nil
	}
	return uc, tr
}

func TestListTeamMembers_AnySignedInPersonSeesNamesButNotEmails(t *testing.T) {
	uc, _ := rosterHarness()

	roster, err := uc.ListTeamMembers(teamMemberCtx(), rosterTeamID)
	require.NoError(t, err)
	require.Len(t, roster, 2)
	assert.Equal(t, "Ada Okafor", roster[0].DisplayName)
	assert.Equal(t, "u1", roster[0].UserID)
	assert.Equal(t, "admin", roster[0].Role)
	for _, m := range roster {
		assert.Empty(t, m.UserEmail, "an ordinary person does not get addresses")
	}
}

func TestListTeamMembers_TeamAdminSeesEmails(t *testing.T) {
	uc, tr := rosterHarness()
	tr.isAdminFn = func(ctx context.Context, teamID, userID string) (bool, error) {
		return teamID == rosterTeamID && userID == "00000000-0000-0000-0000-000000000040", nil
	}

	roster, err := uc.ListTeamMembers(teamMemberCtx(), rosterTeamID)
	require.NoError(t, err)
	require.Len(t, roster, 2)
	assert.Equal(t, "ada@acme.example", roster[0].UserEmail)
	assert.Equal(t, "Ada Okafor", roster[0].DisplayName)
	assert.Equal(t, "bo@acme.example", roster[1].UserEmail)
}

func TestListTeamMembers_GlobalAdminSeesEmails(t *testing.T) {
	uc, _ := rosterHarness()

	roster, err := uc.ListTeamMembers(sessionCtx("00000000-0000-4000-8000-000000000007", auth.RoleAdmin), rosterTeamID)
	require.NoError(t, err)
	require.Len(t, roster, 2)
	assert.Equal(t, "ada@acme.example", roster[0].UserEmail)
}

func TestListTeamMembers_APIKeysAreRefused(t *testing.T) {
	uc, _ := rosterHarness()

	_, err := uc.ListTeamMembers(apiKeyCtx("key-1", "22222222-2222-2222-2222-222222222222"), rosterTeamID)
	assert.ErrorIs(t, err, ErrProjectAccessDenied)
}

func TestListTeamMembers_AnonymousIsRefused(t *testing.T) {
	uc, _ := rosterHarness()

	_, err := uc.ListTeamMembers(context.Background(), rosterTeamID)
	assert.ErrorIs(t, err, ErrProjectAccessDenied)
}

func TestListTeamMembers_UnknownTeamIsNotFound(t *testing.T) {
	uc, tr := rosterHarness()
	tr.getByIDFn = func(ctx context.Context, id string) (port.Team, error) {
		return port.Team{}, port.ErrNotFound
	}

	_, err := uc.ListTeamMembers(teamMemberCtx(), rosterTeamID)
	assert.ErrorIs(t, err, ErrTeamNotFound)
}

// A team the caller cannot see answers like a team that does not exist, on
// reads and on roster writes, so team ids cannot be probed.
func TestTeamRoster_InvisibleTeamLooksMissing(t *testing.T) {
	uc, tr := rosterHarness()
	tr.isVisibleFn = func(context.Context, string, string) (bool, error) { return false, nil }
	tr.upsertMemberFn = func(context.Context, string, string, string) (port.TeamMember, error) {
		t.Fatal("nothing is written to a team the caller cannot see")
		return port.TeamMember{}, nil
	}
	const other = "22222222-2222-2222-2222-222222222222"

	_, err := uc.ListTeamMembers(teamMemberCtx(), rosterTeamID)
	assert.ErrorIs(t, err, ErrTeamNotFound)
	_, err = uc.AddTeamMember(teamMemberCtx(), rosterTeamID, other, "member")
	assert.ErrorIs(t, err, ErrTeamNotFound)
	assert.ErrorIs(t, uc.RemoveTeamMember(teamMemberCtx(), rosterTeamID, other), ErrTeamNotFound)

	// A global admin sees every team.
	_, err = uc.ListTeamMembers(adminCtx(), rosterTeamID)
	require.NoError(t, err)

	// A team the caller can see but does not administer is a plain refusal.
	tr.isVisibleFn = func(context.Context, string, string) (bool, error) { return true, nil }
	_, err = uc.AddTeamMember(teamMemberCtx(), rosterTeamID, other, "member")
	assert.ErrorIs(t, err, ErrProjectAccessDenied)

	tr.getByIDFn = func(context.Context, string) (port.Team, error) { return port.Team{}, port.ErrNotFound }
	_, err = uc.ListTeamMembers(teamMemberCtx(), rosterTeamID)
	assert.ErrorIs(t, err, ErrTeamNotFound, "a missing team gives the same answer")
}
