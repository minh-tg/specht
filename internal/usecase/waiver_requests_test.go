package usecase

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	requestFindingID = "00000000-0000-0000-0000-0000000000f1"
	requestWaiverID  = "00000000-0000-0000-0000-0000000000b1"
	requesterID      = "00000000-0000-0000-0000-0000000000a1"
	approverID       = "00000000-0000-0000-0000-0000000000a2"
)

func waiverRequestUsecase(t *testing.T, role string, wr *mockWaiverRepo) *Usecases {
	t.Helper()
	project := makeProject(true)
	projects := &mockProjectRepo{
		getBySlugFn:     func(context.Context, string) (port.Project, error) { return project, nil },
		effectiveRoleFn: func(context.Context, string, string) (string, error) { return role, nil },
	}
	findings := &mockFindingRepo{
		getByIDFn: func(_ context.Context, id string) (port.Finding, error) {
			if id != requestFindingID {
				return port.Finding{}, port.ErrNotFound
			}
			return port.Finding{ID: id, ProjectID: project.ID, CurrentTitle: "openssh-server: security issue"}, nil
		},
	}
	return New(Deps{Stores: &port.Stores{Projects: projects, Waivers: wr, Findings: findings}})
}

func validWaiverRequest() RequestWaiverInput {
	expires := time.Now().Add(30 * 24 * time.Hour)
	return RequestWaiverInput{
		ProjectSlug: "my-app",
		TargetIDs:   []string{requestFindingID},
		Reason:      "The vulnerable path is not reachable from the public API.",
		ExpiresAt:   &expires,
	}
}

func TestRequestWaiverCreatesPendingRequest(t *testing.T) {
	var got port.CreateWaiverInput
	wr := &mockWaiverRepo{
		listFn: func(context.Context, string) ([]port.Waiver, error) { return nil, nil },
		createWithDetailsFn: func(_ context.Context, in port.CreateWaiverInput) (port.Waiver, error) {
			got = in
			return port.Waiver{ID: requestWaiverID, ProjectID: in.ProjectID, Name: in.Name, Status: in.Status, Reason: in.Reason, RequestedBy: in.RequestedBy}, nil
		},
	}
	uc := waiverRequestUsecase(t, auth.RoleMember, wr)

	resp, err := uc.RequestWaiver(sessionCtx(requesterID, auth.RoleMember), validWaiverRequest())

	require.NoError(t, err)
	assert.Equal(t, WaiverStatusPending, got.Status)
	assert.Equal(t, "requested", got.Event.EventType)
	require.NotNil(t, got.RequestedBy)
	assert.Equal(t, requesterID, *got.RequestedBy)
	require.Len(t, got.Targets, 1)
	assert.Equal(t, requestFindingID, got.Targets[0].FindingID)
	assert.Equal(t, "Waiver request: openssh-server: security issue", got.Name)
	assert.Equal(t, WaiverStatusPending, resp.Status)
}

func TestRequestWaiverRoles(t *testing.T) {
	for role, allowed := range map[string]bool{
		auth.RoleAdmin: true, auth.RoleManager: true, auth.RoleEditor: true,
		auth.RoleMember: true, auth.RoleViewer: true, "guest": false, "": false,
	} {
		t.Run("role "+role, func(t *testing.T) {
			wr := &mockWaiverRepo{
				listFn: func(context.Context, string) ([]port.Waiver, error) { return nil, nil },
				createWithDetailsFn: func(_ context.Context, in port.CreateWaiverInput) (port.Waiver, error) {
					return port.Waiver{ID: requestWaiverID, Status: in.Status}, nil
				},
			}
			_, err := waiverRequestUsecase(t, role, wr).RequestWaiver(sessionCtx(requesterID, auth.RoleMember), validWaiverRequest())
			if allowed {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, ErrProjectAccessDenied)
			}
		})
	}
}

func TestRequestWaiverDeniesAPIKeys(t *testing.T) {
	uc := waiverRequestUsecase(t, auth.RoleAdmin, &mockWaiverRepo{})
	_, err := uc.RequestWaiver(apiKeyCtx("key-1", makeProject(true).ID), validWaiverRequest())
	require.ErrorIs(t, err, ErrProjectAccessDenied, "a request needs a person as requester")
}

func TestRequestWaiverValidation(t *testing.T) {
	longReason := make([]rune, maxWaiverReasonLen+1)
	for i := range longReason {
		longReason[i] = 'x'
	}
	past := time.Now().Add(-time.Hour)
	far := time.Now().Add(maxWaiverRequestAge + 24*time.Hour)
	tests := []struct {
		name   string
		mutate func(*RequestWaiverInput)
		msg    string
	}{
		{"reason missing", func(in *RequestWaiverInput) { in.Reason = "  " }, "reason is required"},
		{"reason too long", func(in *RequestWaiverInput) { in.Reason = string(longReason) }, "reason is longer"},
		{"expiry missing", func(in *RequestWaiverInput) { in.ExpiresAt = nil }, "expires_at is required"},
		{"expiry in the past", func(in *RequestWaiverInput) { in.ExpiresAt = &past }, "must be in the future"},
		{"expiry too far", func(in *RequestWaiverInput) { in.ExpiresAt = &far }, "days ahead"},
		{"no targets", func(in *RequestWaiverInput) { in.TargetIDs = nil }, "at least one finding"},
		{"bad target id", func(in *RequestWaiverInput) { in.TargetIDs = []string{"nope"} }, "invalid finding id"},
		{"foreign finding", func(in *RequestWaiverInput) {
			in.TargetIDs = []string{"00000000-0000-0000-0000-0000000000f9"}
		}, "was not found in this project"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := validWaiverRequest()
			tc.mutate(&in)
			wr := &mockWaiverRepo{listFn: func(context.Context, string) ([]port.Waiver, error) { return nil, nil }}
			_, err := waiverRequestUsecase(t, auth.RoleMember, wr).RequestWaiver(sessionCtx(requesterID, auth.RoleMember), in)
			require.ErrorIs(t, err, ErrInvalidWaiverRequest)
			assert.Contains(t, err.Error(), tc.msg)
		})
	}
}

func TestRequestWaiverRejectsDuplicatePendingRequest(t *testing.T) {
	wr := &mockWaiverRepo{
		listFn: func(context.Context, string) ([]port.Waiver, error) {
			return []port.Waiver{{ID: requestWaiverID, Status: WaiverStatusPending}, {ID: "approved-1", Status: WaiverStatusApproved}}, nil
		},
		listFindingTargetsByWaiverIDsFn: func(_ context.Context, ids []string) ([]port.WaiverFindingTarget, error) {
			assert.Equal(t, []string{requestWaiverID}, ids, "only pending requests are checked")
			return []port.WaiverFindingTarget{{WaiverID: requestWaiverID, FindingID: requestFindingID}}, nil
		},
	}
	_, err := waiverRequestUsecase(t, auth.RoleMember, wr).RequestWaiver(sessionCtx(requesterID, auth.RoleMember), validWaiverRequest())
	require.ErrorIs(t, err, ErrWaiverRequestExists)
}

func pendingWaiver(requestedBy string, expires *time.Time) port.Waiver {
	return port.Waiver{
		ID: requestWaiverID, ProjectID: makeProject(true).ID, Status: WaiverStatusPending,
		RequestedBy: &requestedBy, ExpiresAt: expires,
	}
}

func decideRecorder(got *port.WaiverDecision, result string) func(context.Context, string, string, port.WaiverDecision) (port.Waiver, error) {
	return func(_ context.Context, id, _ string, d port.WaiverDecision) (port.Waiver, error) {
		*got = d
		return port.Waiver{ID: id, Status: result}, nil
	}
}

func TestApproveWaiver(t *testing.T) {
	future := time.Now().Add(time.Hour)
	var got port.WaiverDecision
	wr := &mockWaiverRepo{
		getByIDFn: func(context.Context, string, string) (port.Waiver, error) {
			return pendingWaiver(requesterID, &future), nil
		},
		decideFn: decideRecorder(&got, WaiverStatusApproved),
	}
	uc := waiverRequestUsecase(t, auth.RoleManager, wr)

	resp, err := uc.ApproveWaiver(sessionCtx(approverID, auth.RoleMember), "my-app", requestWaiverID, " ok ")

	require.NoError(t, err)
	assert.Equal(t, WaiverStatusApproved, resp.Status)
	assert.Equal(t, WaiverStatusApproved, got.Status)
	assert.Equal(t, approverID, got.ActorID)
	assert.Equal(t, "ok", got.Note)
	assert.Equal(t, "approved", got.Event.EventType)
	assert.JSONEq(t, `{"note":"ok","self_approved":false}`, string(got.Event.Metadata))
}

func TestDecideWaiverRoles(t *testing.T) {
	future := time.Now().Add(time.Hour)
	for _, tc := range []struct {
		role    string
		allowed bool
	}{
		{auth.RoleAdmin, true},
		{auth.RoleManager, true},
		{auth.RoleEditor, true},
		{auth.RoleMember, false},
		{auth.RoleViewer, false},
	} {
		t.Run("approve as "+tc.role, func(t *testing.T) {
			var got port.WaiverDecision
			wr := &mockWaiverRepo{
				getByIDFn: func(context.Context, string, string) (port.Waiver, error) {
					return pendingWaiver(requesterID, &future), nil
				},
				decideFn: decideRecorder(&got, WaiverStatusApproved),
			}
			_, err := waiverRequestUsecase(t, tc.role, wr).ApproveWaiver(sessionCtx(approverID, auth.RoleMember), "my-app", requestWaiverID, "")
			if tc.allowed {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, ErrProjectAccessDenied)
				assert.Empty(t, got.Status, "a denied caller must not reach the store")
			}
		})
	}
}

func TestApproveWaiverSelfApproval(t *testing.T) {
	future := time.Now().Add(time.Hour)
	var got port.WaiverDecision
	wr := &mockWaiverRepo{
		getByIDFn: func(context.Context, string, string) (port.Waiver, error) {
			return pendingWaiver(requesterID, &future), nil
		},
		decideFn: decideRecorder(&got, WaiverStatusApproved),
	}

	_, err := waiverRequestUsecase(t, auth.RoleManager, wr).ApproveWaiver(sessionCtx(requesterID, auth.RoleMember), "my-app", requestWaiverID, "")
	require.ErrorIs(t, err, ErrWaiverSelfApproval)
	assert.Empty(t, got.Status)

	resp, err := waiverRequestUsecase(t, auth.RoleManager, wr).ApproveWaiver(sessionCtx(requesterID, auth.RoleAdmin), "my-app", requestWaiverID, "")
	require.NoError(t, err, "a global admin may approve their own request")
	assert.Equal(t, WaiverStatusApproved, resp.Status)
	assert.JSONEq(t, `{"note":"","self_approved":true}`, string(got.Event.Metadata))
}

func TestApproveWaiverRefusesExpiredAndDecidedRequests(t *testing.T) {
	past := time.Now().Add(-time.Minute)
	future := time.Now().Add(time.Hour)
	for name, tc := range map[string]struct {
		waiver port.Waiver
		want   error
	}{
		"expired": {pendingWaiver(requesterID, &past), ErrWaiverExpired},
		"approved": {func() port.Waiver {
			w := pendingWaiver(requesterID, &future)
			w.Status = WaiverStatusApproved
			return w
		}(), ErrWaiverNotPending},
		"rejected": {func() port.Waiver {
			w := pendingWaiver(requesterID, &future)
			w.Status = WaiverStatusRejected
			return w
		}(), ErrWaiverNotPending},
	} {
		t.Run(name, func(t *testing.T) {
			wr := &mockWaiverRepo{getByIDFn: func(context.Context, string, string) (port.Waiver, error) { return tc.waiver, nil }}
			_, err := waiverRequestUsecase(t, auth.RoleManager, wr).ApproveWaiver(sessionCtx(approverID, auth.RoleMember), "my-app", requestWaiverID, "")
			require.ErrorIs(t, err, tc.want)
		})
	}
}

func TestApproveWaiverSurfacesConcurrentDecision(t *testing.T) {
	future := time.Now().Add(time.Hour)
	wr := &mockWaiverRepo{
		getByIDFn: func(context.Context, string, string) (port.Waiver, error) {
			return pendingWaiver(requesterID, &future), nil
		},
		decideFn: func(context.Context, string, string, port.WaiverDecision) (port.Waiver, error) {
			return port.Waiver{}, port.ErrWaiverNotPending
		},
	}
	_, err := waiverRequestUsecase(t, auth.RoleManager, wr).ApproveWaiver(sessionCtx(approverID, auth.RoleMember), "my-app", requestWaiverID, "")
	require.ErrorIs(t, err, ErrWaiverNotPending, "another approver decided between the read and the write")
}

func TestRejectWaiverNeedsANote(t *testing.T) {
	future := time.Now().Add(time.Hour)
	var got port.WaiverDecision
	wr := &mockWaiverRepo{
		getByIDFn: func(context.Context, string, string) (port.Waiver, error) {
			return pendingWaiver(requesterID, &future), nil
		},
		decideFn: decideRecorder(&got, WaiverStatusRejected),
	}
	uc := waiverRequestUsecase(t, auth.RoleManager, wr)

	_, err := uc.RejectWaiver(sessionCtx(approverID, auth.RoleMember), "my-app", requestWaiverID, "  ")
	require.ErrorIs(t, err, ErrInvalidWaiverRequest)

	resp, err := uc.RejectWaiver(sessionCtx(approverID, auth.RoleMember), "my-app", requestWaiverID, "Fix it instead.")
	require.NoError(t, err)
	assert.Equal(t, WaiverStatusRejected, resp.Status)
	assert.Equal(t, "Fix it instead.", got.Note)
	assert.Equal(t, "rejected", got.Event.EventType)
}

func TestWithdrawWaiverIsForTheRequesterOnly(t *testing.T) {
	var got port.WaiverDecision
	wr := &mockWaiverRepo{
		getByIDFn: func(context.Context, string, string) (port.Waiver, error) {
			return pendingWaiver(requesterID, nil), nil
		},
		decideFn: decideRecorder(&got, WaiverStatusWithdrawn),
	}
	uc := waiverRequestUsecase(t, auth.RoleAdmin, wr)

	_, err := uc.WithdrawWaiver(sessionCtx(approverID, auth.RoleMember), "my-app", requestWaiverID)
	require.ErrorIs(t, err, ErrProjectAccessDenied, "even an admin cannot withdraw someone else's request")

	resp, err := waiverRequestUsecase(t, auth.RoleMember, wr).WithdrawWaiver(sessionCtx(requesterID, auth.RoleMember), "my-app", requestWaiverID)
	require.NoError(t, err)
	assert.Equal(t, WaiverStatusWithdrawn, resp.Status)
	assert.Equal(t, "withdrawn", got.Event.EventType)
}

func TestDecideWaiverMissingWaiver(t *testing.T) {
	wr := &mockWaiverRepo{getByIDFn: func(context.Context, string, string) (port.Waiver, error) {
		return port.Waiver{}, port.ErrNotFound
	}}
	_, err := waiverRequestUsecase(t, auth.RoleManager, wr).ApproveWaiver(sessionCtx(approverID, auth.RoleMember), "my-app", requestWaiverID, "")
	require.True(t, errors.Is(err, port.ErrNotFound))
}

func TestCreateWaiverRequiresAnExplicitScope(t *testing.T) {
	project := makeProject(true)
	created := 0
	wr := &mockWaiverRepo{createWithDetailsFn: func(_ context.Context, in port.CreateWaiverInput) (port.Waiver, error) {
		created++
		assert.Equal(t, WaiverStatusApproved, in.Status, "direct creation by a manager is approved")
		return port.Waiver{ID: requestWaiverID, ProjectID: in.ProjectID, Status: in.Status}, nil
	}}
	uc := waiverUsecaseForProject(project, wr, auth.RoleManager)
	ctx := sessionCtx(approverID, auth.RoleMember)

	_, err := uc.CreateWaiver(ctx, CreateWaiverInput{ProjectSlug: "my-app", Name: "everything"})
	require.ErrorIs(t, err, ErrWaiverScopeRequired)

	_, err = uc.CreateWaiver(ctx, CreateWaiverInput{ProjectSlug: "my-app", Name: "everything", ScopeAll: true, TargetIDs: []string{requestFindingID}})
	require.ErrorIs(t, err, ErrInvalidWaiverRequest, "scope all cannot be combined with a scope")

	_, err = uc.CreateWaiver(ctx, CreateWaiverInput{ProjectSlug: "my-app", Name: "everything", ScopeAll: true})
	require.NoError(t, err)
	_, err = uc.CreateWaiver(ctx, CreateWaiverInput{ProjectSlug: "my-app", Name: "one finding", TargetIDs: []string{requestFindingID}})
	require.NoError(t, err)
	assert.Equal(t, 2, created)
}

func TestUpdateWaiverCannotSilentlyBecomeABlanket(t *testing.T) {
	project := makeProject(true)
	wr := &mockWaiverRepo{
		getByIDFn:        waiverExists,
		listConditionsFn: func(context.Context, string) ([]port.WaiverCondition, error) { return nil, nil },
		listContextsFn:   func(context.Context, string) ([]port.WaiverContext, error) { return nil, nil },
		listFindingTargetsFn: func(context.Context, string) ([]port.WaiverFindingTarget, error) {
			return []port.WaiverFindingTarget{{FindingID: requestFindingID}}, nil
		},
		updateWithDetailsFn: func(context.Context, port.Waiver, *port.WaiverExpiry, *[]port.WaiverCondition, *[]port.WaiverContext, *[]port.WaiverFindingTarget, port.WaiverEventInput) (port.Waiver, error) {
			return port.Waiver{ID: requestWaiverID, ProjectID: project.ID}, nil
		},
	}
	uc := waiverUsecaseForProject(project, wr, auth.RoleManager)
	ctx := sessionCtx(approverID, auth.RoleMember)

	_, err := uc.UpdateWaiver(ctx, UpdateWaiverInput{WaiverID: requestWaiverID, ProjectSlug: "my-app", TargetIDs: []string{}})
	require.ErrorIs(t, err, ErrWaiverScopeRequired, "clearing the only target would leave no scope")

	_, err = uc.UpdateWaiver(ctx, UpdateWaiverInput{WaiverID: requestWaiverID, ProjectSlug: "my-app", TargetIDs: []string{}, ScopeAll: true})
	require.NoError(t, err, "an explicit scope of all is allowed")

	_, err = uc.UpdateWaiver(ctx, UpdateWaiverInput{WaiverID: requestWaiverID, ProjectSlug: "my-app", Name: "renamed"})
	require.NoError(t, err, "an update that leaves the scope alone needs no scope check")
}

func TestListWaiversFiltersByStatus(t *testing.T) {
	wr := &mockWaiverRepo{listFn: func(context.Context, string) ([]port.Waiver, error) {
		return []port.Waiver{
			{ID: "1", Status: WaiverStatusPending},
			{ID: "2", Status: WaiverStatusApproved},
			{ID: "3", Status: WaiverStatusRejected},
		}, nil
	}}
	uc := waiverRequestUsecase(t, auth.RoleMember, wr)
	uc.deps.Stores.Projects.(*mockProjectRepo).isMemberFn = func(context.Context, string, string) (bool, error) { return true, nil }
	ctx := sessionCtx(requesterID, auth.RoleMember)

	all, err := uc.ListWaivers(ctx, "my-app")
	require.NoError(t, err)
	assert.Len(t, all, 3)

	some, err := uc.ListWaivers(ctx, "my-app", WaiverStatusPending, WaiverStatusRejected)
	require.NoError(t, err)
	require.Len(t, some, 2)
	assert.Equal(t, []string{"1", "3"}, []string{some[0].ID, some[1].ID})
}

func TestListWaiversAttachesScopeRows(t *testing.T) {
	wr := &mockWaiverRepo{
		listFn: func(context.Context, string) ([]port.Waiver, error) {
			return []port.Waiver{
				{ID: "w1", Status: WaiverStatusPending},
				{ID: "w2", Status: WaiverStatusApproved},
				{ID: "w3", Status: WaiverStatusRejected},
			}, nil
		},
		listConditionsByWaiverIDsFn: func(_ context.Context, ids []string) ([]port.WaiverCondition, error) {
			assert.Equal(t, []string{"w1", "w2"}, ids, "only the waivers that pass the status filter are read")
			return []port.WaiverCondition{{WaiverID: "w2", Field: "severity_rank", Operator: "lte", Value: "2"}}, nil
		},
		listContextsByWaiverIDsFn: func(context.Context, []string) ([]port.WaiverContext, error) {
			return []port.WaiverContext{{WaiverID: "w2", EnvironmentID: "env-1"}}, nil
		},
		listFindingTargetsByWaiverIDsFn: func(context.Context, []string) ([]port.WaiverFindingTarget, error) {
			return []port.WaiverFindingTarget{
				{WaiverID: "w1", FindingID: requestFindingID},
				{WaiverID: "w1", FindingID: "00000000-0000-0000-0000-0000000000f2"},
				{WaiverID: "unknown", FindingID: "ignored"},
			}, nil
		},
	}
	uc := waiverRequestUsecase(t, auth.RoleMember, wr)
	uc.deps.Stores.Projects.(*mockProjectRepo).isMemberFn = func(context.Context, string, string) (bool, error) { return true, nil }

	got, err := uc.ListWaivers(sessionCtx(requesterID, auth.RoleMember), "my-app", WaiverStatusPending, WaiverStatusApproved)

	require.NoError(t, err)
	require.Len(t, got, 2)
	require.Len(t, got[0].Targets, 2, "a pending request names the findings it covers")
	assert.Equal(t, requestFindingID, got[0].Targets[0].FindingID)
	assert.Empty(t, got[0].Conditions)
	require.Len(t, got[1].Conditions, 1)
	require.Len(t, got[1].Contexts, 1)
	assert.Empty(t, got[1].Targets)
	assert.NotNil(t, got[1].Targets, "an empty set stays an array in the JSON, never null")
}

func TestListWaiversSkipsTheScopeReadsWhenNothingMatches(t *testing.T) {
	wr := &mockWaiverRepo{listFn: func(context.Context, string) ([]port.Waiver, error) {
		return []port.Waiver{{ID: "w1", Status: WaiverStatusApproved}}, nil
	}}
	uc := waiverRequestUsecase(t, auth.RoleMember, wr)
	uc.deps.Stores.Projects.(*mockProjectRepo).isMemberFn = func(context.Context, string, string) (bool, error) { return true, nil }

	got, err := uc.ListWaivers(sessionCtx(requesterID, auth.RoleMember), "my-app", WaiverStatusPending)

	require.NoError(t, err)
	assert.Empty(t, got, "the scope readers are not set on the mock, so any call would fail the test")
	assert.NotNil(t, got)
}
