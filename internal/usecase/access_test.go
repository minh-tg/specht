package usecase

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
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
