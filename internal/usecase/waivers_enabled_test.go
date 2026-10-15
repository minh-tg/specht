package usecase

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	enabledTestWaiverID = "00000000-0000-0000-0000-0000000000b1"
	enabledTestActorID  = "00000000-0000-0000-0000-000000000040"
)

type waiverSwitch struct {
	name  string
	want  bool
	event string
	call  func(*Usecases, context.Context, string, *time.Time) (*WaiverResponse, error)
}

func waiverSwitches() []waiverSwitch {
	return []waiverSwitch{
		{"revoke", false, "revoked", func(uc *Usecases, ctx context.Context, actor string, expected *time.Time) (*WaiverResponse, error) {
			return uc.RevokeWaiver(ctx, "my-app", enabledTestWaiverID, actor, expected)
		}},
		{"restore", true, "restored", func(uc *Usecases, ctx context.Context, actor string, expected *time.Time) (*WaiverResponse, error) {
			return uc.RestoreWaiver(ctx, "my-app", enabledTestWaiverID, actor, expected)
		}},
	}
}

func TestRevokeAndRestoreWaiverNameTheWantedStateAndRecordTheActor(t *testing.T) {
	project := makeProject(true)
	expected := time.Date(2026, 10, 15, 9, 12, 44, 123456000, time.UTC)
	for _, sw := range waiverSwitches() {
		t.Run(sw.name, func(t *testing.T) {
			var got port.WaiverEnabledChange
			wr := &mockWaiverRepo{
				setEnabledFn: func(_ context.Context, id, projectID string, change port.WaiverEnabledChange) (port.Waiver, error) {
					assert.Equal(t, enabledTestWaiverID, id)
					assert.Equal(t, project.ID, projectID)
					got = change
					return port.Waiver{ID: id, ProjectID: projectID, Enabled: change.Enabled, Status: WaiverStatusApproved}, nil
				},
			}
			uc := waiverUsecaseForProject(project, wr, auth.RoleManager)

			resp, err := sw.call(uc, sessionCtx(enabledTestActorID, auth.RoleMember), enabledTestActorID, &expected)
			require.NoError(t, err)
			assert.Equal(t, sw.want, resp.Enabled)
			assert.Equal(t, sw.want, got.Enabled)
			assert.Equal(t, sw.event, got.Event.EventType)
			require.NotNil(t, got.Event.ActorID)
			assert.Equal(t, enabledTestActorID, *got.Event.ActorID)
			require.NotNil(t, got.ExpectedUpdatedAt)
			assert.True(t, got.ExpectedUpdatedAt.Equal(expected))
			assert.JSONEq(t, `{}`, string(got.Event.Metadata))
		})
	}
}

func TestRevokeAndRestoreWaiverWithoutPreconditionLeaveItUnset(t *testing.T) {
	project := makeProject(true)
	for _, sw := range waiverSwitches() {
		t.Run(sw.name, func(t *testing.T) {
			wr := &mockWaiverRepo{
				setEnabledFn: func(_ context.Context, id, projectID string, change port.WaiverEnabledChange) (port.Waiver, error) {
					assert.Nil(t, change.ExpectedUpdatedAt)
					return port.Waiver{ID: id, ProjectID: projectID}, nil
				},
			}
			_, err := sw.call(waiverUsecaseForProject(project, wr, auth.RoleManager), sessionCtx("m", auth.RoleMember), "m", nil)
			require.NoError(t, err)
		})
	}
}

func TestRevokeAndRestoreWaiverNeedAProjectManager(t *testing.T) {
	project := makeProject(true)
	for _, sw := range waiverSwitches() {
		for _, role := range []string{auth.RoleViewer, auth.RoleMember} {
			t.Run(sw.name+"/"+role, func(t *testing.T) {
				wr := &mockWaiverRepo{} // any store call fails the test as unexpected
				uc := waiverUsecaseForProject(project, wr, role)
				_, err := sw.call(uc, sessionCtx("someone", auth.RoleMember), "someone", nil)
				require.ErrorIs(t, err, ErrProjectAccessDenied)
			})
		}
		for _, role := range []string{auth.RoleManager, auth.RoleEditor} {
			t.Run(sw.name+"/"+role+" allowed", func(t *testing.T) {
				wr := &mockWaiverRepo{
					setEnabledFn: func(_ context.Context, id, projectID string, _ port.WaiverEnabledChange) (port.Waiver, error) {
						return port.Waiver{ID: id, ProjectID: projectID}, nil
					},
				}
				uc := waiverUsecaseForProject(project, wr, role)
				_, err := sw.call(uc, sessionCtx("someone", auth.RoleMember), "someone", nil)
				require.NoError(t, err)
			})
		}
	}
}

func TestRevokeAndRestoreWaiverRejectMalformedIDsAndProjects(t *testing.T) {
	project := makeProject(true)
	admin := sessionCtx("admin", auth.RoleAdmin)
	uc := waiverUsecaseForProject(project, &mockWaiverRepo{}, "")
	_, err := uc.RevokeWaiver(admin, "my-app", "not-a-uuid", "admin", nil)
	require.Error(t, err)
	_, err = uc.RestoreWaiver(admin, "my-app", "not-a-uuid", "admin", nil)
	require.Error(t, err)

	lookupErr := errors.New("project lookup failed")
	missing := New(Deps{Stores: &port.Stores{
		Projects: &mockProjectRepo{getBySlugFn: func(context.Context, string) (port.Project, error) {
			return port.Project{}, lookupErr
		}},
		Waivers: &mockWaiverRepo{},
	}})
	_, err = missing.RevokeWaiver(admin, "gone", enabledTestWaiverID, "admin", nil)
	require.ErrorIs(t, err, lookupErr)
}

func TestRevokeAndRestoreWaiverKeepTheStoreRefusalsMatchable(t *testing.T) {
	project := makeProject(true)
	for _, sw := range waiverSwitches() {
		for _, refusal := range []error{
			ErrWaiverChanged, ErrWaiverLapsed, ErrWaiverNotApproved, port.ErrNotFound, errors.New("disk full"),
		} {
			t.Run(fmt.Sprintf("%s/%v", sw.name, refusal), func(t *testing.T) {
				wr := &mockWaiverRepo{
					setEnabledFn: func(context.Context, string, string, port.WaiverEnabledChange) (port.Waiver, error) {
						return port.Waiver{}, refusal
					},
				}
				resp, err := sw.call(waiverUsecaseForProject(project, wr, auth.RoleManager), sessionCtx("m", auth.RoleMember), "m", nil)
				assert.Nil(t, resp)
				require.ErrorIs(t, err, refusal)
			})
		}
	}
}

// A revoke hands back the version a later Undo sends as its precondition. The
// precondition is compared to the microsecond in SQL, so the response must not
// round it to the second.
func TestWaiverResponseUpdatedAtRoundTripsToTheStoredVersion(t *testing.T) {
	stored := time.Date(2026, 10, 15, 9, 12, 44, 123456000, time.UTC)
	resp := toWaiver(port.Waiver{ID: "w1", UpdatedAt: stored, CreatedAt: stored})

	parsed, err := time.Parse(time.RFC3339Nano, resp.UpdatedAt)
	require.NoError(t, err)
	assert.True(t, parsed.Equal(stored), "updated_at %q lost precision", resp.UpdatedAt)
}
