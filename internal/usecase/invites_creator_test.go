package usecase

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
)

// The claim re-checks the creator with auth.MayGrantInvite. CreateInvite must
// accept exactly the cases that function accepts, so a link is never refused
// at claim time for a creator who could have made it that same minute, and
// never accepted for one who could not.
func TestCreateInvite_AgreesWithTheRuleTheClaimReapplies(t *testing.T) {
	roles := []string{"", auth.RoleMember, auth.RoleManager, auth.RoleAdmin}
	for _, global := range []string{auth.RoleViewer, auth.RoleAdmin} {
		for _, direct := range roles {
			for _, team := range roles {
				for _, inviteRole := range []string{auth.RoleMember, auth.RoleManager} {
					name := "global=" + global + " direct=" + direct + " team=" + team + " invite=" + inviteRole
					t.Run(name, func(t *testing.T) {
						effective := direct
						if auth.RoleRank(team) > auth.RoleRank(effective) {
							effective = team
						}
						projects := &mockProjectRepo{
							getBySlugFn: func(context.Context, string) (port.Project, error) {
								return port.Project{ID: "00000000-0000-0000-0000-000000000001", Slug: "payments"}, nil
							},
							effectiveRoleFn: func(context.Context, string, string) (string, error) {
								if effective == "" {
									return "", port.ErrNotFound
								}
								return effective, nil
							},
							getMemberFn: func(_ context.Context, projectID, userID string) (port.ProjectMember, error) {
								if direct == "" {
									return port.ProjectMember{}, port.ErrNotFound
								}
								return port.ProjectMember{ProjectID: projectID, UserID: userID, Role: direct}, nil
							},
						}
						uc := New(Deps{Stores: &port.Stores{Projects: projects, Invites: newFakeInvites()}})

						_, err := uc.CreateInvite(sessionCtx("00000000-0000-0000-0000-0000000000b1", global), "payments", CreateInviteInput{Role: inviteRole})

						allowed := auth.MayGrantInvite(auth.InviteGrantor{Active: true, GlobalRole: global, DirectRole: direct, TeamRole: team}, inviteRole)
						if allowed {
							assert.NoError(t, err)
						} else {
							assert.ErrorIs(t, err, ErrProjectAccessDenied)
						}
					})
				}
			}
		}
	}
}
