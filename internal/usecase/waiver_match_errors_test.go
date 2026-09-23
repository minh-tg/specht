package usecase

import (
	"context"
	"errors"
	"testing"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
	"github.com/stretchr/testify/require"
)

func TestCheckWaiverMatchReportsFindingLookupFailure(t *testing.T) {
	_, findings, _, uc := testCheckWaiverMatchDeps(t)
	storeErr := errors.New("finding lookup failed")
	findings.getByIDFn = func(context.Context, string) (port.Finding, error) {
		return port.Finding{}, storeErr
	}

	_, err := uc.CheckWaiverMatch(
		sessionCtx("admin", auth.RoleAdmin),
		"my-app",
		"00000000-0000-0000-0000-0000000000a1",
	)

	require.ErrorIs(t, err, storeErr)
}

func TestCheckWaiverMatchDeniesUsersWithoutProjectAccess(t *testing.T) {
	projects, findings, _, uc := testCheckWaiverMatchDeps(t)
	project := makeProject(true)
	findingID := "00000000-0000-0000-0000-0000000000a1"
	findings.getByIDFn = func(context.Context, string) (port.Finding, error) {
		return port.Finding{ID: findingID, ProjectID: project.ID}, nil
	}
	projects.effectiveRoleFn = func(context.Context, string, string) (string, error) {
		return "", port.ErrNotFound
	}

	_, err := uc.CheckWaiverMatch(sessionCtx("outsider", auth.RoleViewer), "my-app", findingID)

	require.ErrorIs(t, err, ErrProjectAccessDenied)
}
