package usecase

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xMinhx/specht/internal/auth"
	"github.com/xMinhx/specht/internal/port"
)

// findingFixtureProjectID is the project that makeFindingRow/makeFinding rows
// belong to (see makeFindingRow in usecase_test.go).
const findingFixtureProjectID = "00000000-0000-0000-0000-000000000001"

// findingScopeCtx returns a context carrying an authenticated session-user
// identity. The finding access checks require an identity (nil is denied);
// session users are global and pass regardless of the ProjectID field, which
// only gates API-key principals. The project ID is supplied to keep the
// fixture close to the real project-scoped shapes used elsewhere.
func findingScopeCtx(projectID string) context.Context {
	return auth.ContextWithIdentity(context.Background(), &auth.Identity{
		UserID:    "00000000-0000-0000-0000-000000000040",
		ProjectID: projectID,
	})
}

func TestCheckFindingProjectIDAccess_SessionUserInProjectAllowed(t *testing.T) {
	err := checkFindingProjectIDAccess(findingScopeCtx(findingFixtureProjectID), findingFixtureProjectID)
	assert.NoError(t, err)
}

// A session user without a project scope is authenticated but global:
// the check must allow them, leaving cross-project enforcement to the
// route-level RequireRole/enforceProjectAccess layers.
func TestCheckFindingProjectIDAccess_SessionUserWithoutProjectAllowed(t *testing.T) {
	ctx := auth.ContextWithIdentity(context.Background(), &auth.Identity{UserID: "u1"})
	err := checkFindingProjectIDAccess(ctx, findingFixtureProjectID)
	assert.NoError(t, err)
}

// A ProjectID field on a session identity does not restrict it: only API-key
// principals are project-gated. This guards against re-breaking session users
// by gating on the ProjectID field instead of IsAPIKey.
func TestCheckFindingProjectIDAccess_SessionUserScopeNotEnforced(t *testing.T) {
	err := checkFindingProjectIDAccess(findingScopeCtx("00000000-0000-0000-0000-000000000099"), findingFixtureProjectID)
	assert.NoError(t, err)
}

func TestCheckFindingProjectIDAccess_APIKeyInProjectAllowed(t *testing.T) {
	ctx := auth.ContextWithIdentity(context.Background(), &auth.Identity{
		UserID:    "key-1",
		ProjectID: findingFixtureProjectID,
		IsAPIKey:  true,
	})
	assert.NoError(t, checkFindingProjectIDAccess(ctx, findingFixtureProjectID))
}

func TestCheckFindingProjectIDAccess_APIKeyCrossProjectDenied(t *testing.T) {
	ctx := auth.ContextWithIdentity(context.Background(), &auth.Identity{
		UserID:    "key-1",
		ProjectID: "00000000-0000-0000-0000-000000000099",
		IsAPIKey:  true,
	})
	err := checkFindingProjectIDAccess(ctx, findingFixtureProjectID)
	assert.ErrorIs(t, err, ErrProjectAccessDenied)
}

// Regression: a nil context identity must not bypass the project check.
func TestCheckFindingProjectIDAccess_NoIdentityDenied(t *testing.T) {
	err := checkFindingProjectIDAccess(context.Background(), findingFixtureProjectID)
	assert.ErrorIs(t, err, ErrProjectAccessDenied)
}

func TestCheckFindingRowsProjectAccess_SessionUserCrossProjectAllowed(t *testing.T) {
	// Session users are global: a rows check must not deny a session
	// identity even when the rows belong to other projects.
	err := checkFindingRowsProjectAccess(
		findingScopeCtx("00000000-0000-0000-0000-000000000099"),
		[]port.Finding{makeFindingRow(1)},
	)
	assert.NoError(t, err)
}

func TestCheckFindingRowsProjectAccess_NoIdentityDenied(t *testing.T) {
	err := checkFindingRowsProjectAccess(context.Background(), []port.Finding{makeFindingRow(1)})
	assert.ErrorIs(t, err, ErrProjectAccessDenied)
}

// Regression: a persistence failure (e.g. DB down) must not be masked as
// ErrFindingNotFound. Only a true port.ErrNotFound from the store maps to
// the public not-found sentinel; everything else propagates so the handler
// layer can surface a 500 instead of a 404.
func TestFindingWithProjectAccess_StoreErrorNotMaskedAsNotFound(t *testing.T) {
	storeErr := fmt.Errorf("finding store: %w", context.DeadlineExceeded)
	fr := &mockFindingRepo{}
	fr.getByIDFn = func(ctx context.Context, id string) (port.Finding, error) {
		return port.Finding{}, storeErr
	}

	uc := New(Deps{Stores: &port.Stores{Findings: fr}})

	finding, err := uc.findingWithProjectAccess(
		findingScopeCtx(findingFixtureProjectID),
		uuid.MustParse("00000000-0000-0000-0000-000000000021"),
	)
	assert.Equal(t, port.Finding{}, finding)
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrFindingNotFound)
	// The underlying store error must survive the helper for logging and
	// for the handler layer to distinguish outages from not-found.
	assert.ErrorIs(t, err, storeErr)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

// The access check entry point used by evidence/reachability/triage callers
// must follow the same contract: only port.ErrNotFound becomes
// ErrFindingNotFound.
func TestCheckFindingProjectAccess_StoreErrorNotMaskedAsNotFound(t *testing.T) {
	storeErr := fmt.Errorf("db unavailable")
	fr := &mockFindingRepo{}
	fr.getByIDFn = func(ctx context.Context, id string) (port.Finding, error) {
		return port.Finding{}, storeErr
	}

	uc := New(Deps{Stores: &port.Stores{Findings: fr}})

	err := uc.checkFindingProjectAccess(
		findingScopeCtx(findingFixtureProjectID),
		uuid.MustParse("00000000-0000-0000-0000-000000000021"),
	)
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrFindingNotFound)
	assert.ErrorIs(t, err, storeErr)
}

// A true store-level not-found must keep mapping to the public sentinel.
func TestCheckFindingProjectAccess_StoreNotFoundMapsToErrFindingNotFound(t *testing.T) {
	fr := &mockFindingRepo{}
	fr.getByIDFn = func(ctx context.Context, id string) (port.Finding, error) {
		return port.Finding{}, port.ErrNotFound
	}

	uc := New(Deps{Stores: &port.Stores{Findings: fr}})

	err := uc.checkFindingProjectAccess(
		findingScopeCtx(findingFixtureProjectID),
		uuid.MustParse("00000000-0000-0000-0000-000000000021"),
	)
	assert.ErrorIs(t, err, ErrFindingNotFound)
}
