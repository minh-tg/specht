package usecase

import (
	"context"
	"errors"
	"testing"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
	"github.com/stretchr/testify/require"
)

func TestWaiverOperationsReportProjectLookupFailures(t *testing.T) {
	projectErr := errors.New("project lookup failed")
	admin := sessionCtx("admin", auth.RoleAdmin)
	for _, tc := range []struct {
		name string
		call func(*Usecases) error
	}{
		{name: "create", call: func(uc *Usecases) error {
			_, err := uc.CreateWaiver(admin, CreateWaiverInput{ProjectSlug: "missing"})
			return err
		}},
		{name: "list", call: func(uc *Usecases) error {
			_, err := uc.ListWaivers(context.Background(), "missing")
			return err
		}},
		{name: "get", call: func(uc *Usecases) error {
			_, err := uc.GetWaiver(context.Background(), "missing", "waiver-1")
			return err
		}},
		{name: "update", call: func(uc *Usecases) error {
			_, err := uc.UpdateWaiver(admin, UpdateWaiverInput{ProjectSlug: "missing"})
			return err
		}},
		{name: "delete", call: func(uc *Usecases) error {
			return uc.DeleteWaiver(admin, "missing", "waiver-1")
		}},
		{name: "toggle", call: func(uc *Usecases) error {
			_, err := uc.ToggleWaiver(admin, "missing", "waiver-1", "actor-1")
			return err
		}},
		{name: "events", call: func(uc *Usecases) error {
			_, err := uc.ListWaiverEvents(context.Background(), "missing", "waiver-1")
			return err
		}},
		{name: "match", call: func(uc *Usecases) error {
			_, err := uc.CheckWaiverMatch(context.Background(), "missing", "finding-1")
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			projects := &mockProjectRepo{
				getBySlugFn: func(context.Context, string) (port.Project, error) {
					return port.Project{}, projectErr
				},
			}
			uc := New(Deps{Stores: &port.Stores{Projects: projects, Waivers: &mockWaiverRepo{}}})

			require.ErrorIs(t, tc.call(uc), projectErr)
		})
	}
}

func TestWaiverMutationsRequireProjectAdministrator(t *testing.T) {
	project := makeProject(true)
	uc := waiverUsecaseForProject(project, &mockWaiverRepo{}, auth.RoleViewer)
	viewer := sessionCtx("viewer", auth.RoleViewer)
	waiverID := "00000000-0000-0000-0000-0000000000b1"
	for _, tc := range []struct {
		name string
		call func() error
	}{
		{name: "create", call: func() error {
			_, err := uc.CreateWaiver(viewer, CreateWaiverInput{ProjectSlug: "my-app"})
			return err
		}},
		{name: "update", call: func() error {
			_, err := uc.UpdateWaiver(viewer, UpdateWaiverInput{ProjectSlug: "my-app", WaiverID: waiverID})
			return err
		}},
		{name: "delete", call: func() error {
			return uc.DeleteWaiver(viewer, "my-app", waiverID)
		}},
		{name: "toggle", call: func() error {
			_, err := uc.ToggleWaiver(viewer, "my-app", waiverID, "viewer")
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.ErrorIs(t, tc.call(), ErrProjectAccessDenied)
		})
	}
}

func TestWaiverReadsAndMutationsRejectMalformedIDs(t *testing.T) {
	project := makeProject(true)
	uc := waiverUsecaseForProject(project, &mockWaiverRepo{}, "")
	admin := sessionCtx("admin", auth.RoleAdmin)
	for _, tc := range []struct {
		name string
		call func() error
	}{
		{name: "get", call: func() error {
			_, err := uc.GetWaiver(context.Background(), "my-app", "not-a-uuid")
			return err
		}},
		{name: "update", call: func() error {
			_, err := uc.UpdateWaiver(admin, UpdateWaiverInput{ProjectSlug: "my-app", WaiverID: "not-a-uuid"})
			return err
		}},
		{name: "delete", call: func() error {
			return uc.DeleteWaiver(admin, "my-app", "not-a-uuid")
		}},
		{name: "toggle", call: func() error {
			_, err := uc.ToggleWaiver(admin, "my-app", "not-a-uuid", "actor-1")
			return err
		}},
		{name: "events", call: func() error {
			_, err := uc.ListWaiverEvents(context.Background(), "my-app", "not-a-uuid")
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Error(t, tc.call())
		})
	}
}

func TestWaiverOperationsPreserveStoreFailures(t *testing.T) {
	project := makeProject(true)
	storeErr := errors.New("waiver store unavailable")
	waiverID := "00000000-0000-0000-0000-0000000000b1"
	admin := sessionCtx("admin", auth.RoleAdmin)

	t.Run("create", func(t *testing.T) {
		wr := &mockWaiverRepo{createWithDetailsFn: func(context.Context, port.CreateWaiverInput) (port.Waiver, error) {
			return port.Waiver{}, storeErr
		}}
		_, err := waiverUsecaseForProject(project, wr, "").CreateWaiver(admin, CreateWaiverInput{ProjectSlug: "my-app", Name: "exception"})
		require.ErrorIs(t, err, storeErr)
	})

	t.Run("list", func(t *testing.T) {
		wr := &mockWaiverRepo{listFn: func(context.Context, string) ([]port.Waiver, error) {
			return nil, storeErr
		}}
		_, err := waiverUsecaseForProject(project, wr, "").ListWaivers(context.Background(), "my-app")
		require.ErrorIs(t, err, storeErr)
	})

	t.Run("get waiver row", func(t *testing.T) {
		wr := &mockWaiverRepo{getByIDFn: func(context.Context, string, string) (port.Waiver, error) {
			return port.Waiver{}, storeErr
		}}
		_, err := waiverUsecaseForProject(project, wr, "").GetWaiver(context.Background(), "my-app", waiverID)
		require.ErrorIs(t, err, storeErr)
	})

	for _, tc := range []struct {
		name string
		kind string
	}{
		{name: "conditions", kind: "conditions"},
		{name: "contexts", kind: "contexts"},
		{name: "finding targets", kind: "targets"},
	} {
		t.Run("get waiver "+tc.name, func(t *testing.T) {
			wr := &mockWaiverRepo{
				getByIDFn: func(_ context.Context, id, projectID string) (port.Waiver, error) {
					return port.Waiver{ID: id, ProjectID: projectID}, nil
				},
				listConditionsFn: func(context.Context, string) ([]port.WaiverCondition, error) {
					if tc.kind == "conditions" {
						return nil, storeErr
					}
					return nil, nil
				},
				listContextsFn: func(context.Context, string) ([]port.WaiverContext, error) {
					if tc.kind == "contexts" {
						return nil, storeErr
					}
					return nil, nil
				},
				listFindingTargetsFn: func(context.Context, string) ([]port.WaiverFindingTarget, error) {
					if tc.kind == "targets" {
						return nil, storeErr
					}
					return nil, nil
				},
			}
			_, err := waiverUsecaseForProject(project, wr, "").GetWaiver(context.Background(), "my-app", waiverID)
			require.ErrorIs(t, err, storeErr)
		})
	}

	t.Run("update", func(t *testing.T) {
		wr := &mockWaiverRepo{updateWithDetailsFn: func(context.Context, port.Waiver, *port.WaiverExpiry, *[]port.WaiverCondition, *[]port.WaiverContext, *[]port.WaiverFindingTarget, port.WaiverEventInput) (port.Waiver, error) {
			return port.Waiver{}, storeErr
		}}
		_, err := waiverUsecaseForProject(project, wr, "").UpdateWaiver(admin, UpdateWaiverInput{
			ProjectSlug: "my-app", WaiverID: waiverID, Name: "exception",
		})
		require.ErrorIs(t, err, storeErr)
	})

	t.Run("delete", func(t *testing.T) {
		wr := &mockWaiverRepo{deleteFn: func(context.Context, string, string) error { return storeErr }}
		err := waiverUsecaseForProject(project, wr, "").DeleteWaiver(admin, "my-app", waiverID)
		require.ErrorIs(t, err, storeErr)
	})

	t.Run("toggle", func(t *testing.T) {
		wr := &mockWaiverRepo{toggleWithEventFn: func(context.Context, string, string, string) (port.Waiver, error) {
			return port.Waiver{}, storeErr
		}}
		_, err := waiverUsecaseForProject(project, wr, "").ToggleWaiver(admin, "my-app", waiverID, "actor-1")
		require.ErrorIs(t, err, storeErr)
	})

	t.Run("events", func(t *testing.T) {
		wr := &mockWaiverRepo{
			getByIDFn: func(_ context.Context, id, projectID string) (port.Waiver, error) {
				return port.Waiver{ID: id, ProjectID: projectID}, nil
			},
			listEventsFn: func(context.Context, string) ([]port.WaiverEvent, error) {
				return nil, storeErr
			},
		}
		_, err := waiverUsecaseForProject(project, wr, "").ListWaiverEvents(context.Background(), "my-app", waiverID)
		require.ErrorIs(t, err, storeErr)
	})

	t.Run("match", func(t *testing.T) {
		_, _, wr, uc := testCheckWaiverMatchDeps(t)
		wr.listActiveFn = func(context.Context, string) ([]port.Waiver, error) { return nil, storeErr }
		_, err := uc.CheckWaiverMatch(sessionCtx("admin", auth.RoleAdmin), "my-app", "00000000-0000-0000-0000-0000000000a1")
		require.ErrorIs(t, err, storeErr)
	})
}

func TestUpdateWaiverRejectsMalformedContextAndFindingIDs(t *testing.T) {
	project := makeProject(true)
	waiverID := "00000000-0000-0000-0000-0000000000b1"
	for _, tc := range []struct {
		name  string
		input UpdateWaiverInput
	}{
		{
			name: "context ID",
			input: UpdateWaiverInput{
				Contexts: []CreateWaiverContextInput{{ArtifactID: "not-a-uuid"}},
			},
		},
		{
			name: "finding target ID",
			input: UpdateWaiverInput{
				TargetIDs: []string{"not-a-uuid"},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := tc.input
			input.WaiverID = waiverID
			input.ProjectSlug = "my-app"
			uc := waiverUsecaseForProject(project, &mockWaiverRepo{}, "")

			_, err := uc.UpdateWaiver(sessionCtx("admin", auth.RoleAdmin), input)

			require.Error(t, err)
		})
	}
}
