package usecase

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/xMinhx/specht/internal/auth"
	"github.com/xMinhx/specht/internal/port"
)

var (
	ErrProjectAccessDenied = errors.New("project access denied")
	ErrInvalidFindingID    = errors.New("invalid finding id")
)

func (u *Usecases) findingWithProjectAccess(ctx context.Context, findingID uuid.UUID) (port.Finding, error) {
	if u.deps.Stores == nil || u.deps.Stores.Findings == nil {
		return port.Finding{}, fmt.Errorf("check finding project: finding store unavailable")
	}

	finding, err := u.deps.Stores.Findings.GetByID(ctx, findingID.String())
	if err != nil {
		if errors.Is(err, port.ErrNotFound) {
			return port.Finding{}, ErrFindingNotFound
		}
		// Persistence failures (DB down, …) must not surface as not-found:
		// propagate the wrapped error so callers can log it and handlers map
		// it to a 500 instead of a misleading 404.
		return port.Finding{}, fmt.Errorf("check finding project: %w", err)
	}
	if err := checkFindingProjectIDAccess(ctx, finding.ProjectID); err != nil {
		return port.Finding{}, err
	}
	return finding, nil
}

func (u *Usecases) checkFindingProjectAccess(ctx context.Context, findingID uuid.UUID) error {
	_, err := u.findingWithProjectAccess(ctx, findingID)
	return err
}

func checkFindingRowsProjectAccess(ctx context.Context, findings []port.Finding) error {
	for _, finding := range findings {
		if err := checkFindingProjectIDAccess(ctx, finding.ProjectID); err != nil {
			return err
		}
	}
	return nil
}

func checkFindingProjectIDAccess(ctx context.Context, findingProjectID string) error {
	// Deny unauthenticated principals outright: no identity means there is
	// nothing to authorize against.
	ident := auth.ContextIdentity(ctx)
	if ident == nil {
		return ErrProjectAccessDenied
	}
	// Project-scoped principals (API keys) must match the finding's project.
	// Session users without a project scope are authenticated but global;
	// cross-project access for them is enforced at the route level via
	// RequireRole and enforceProjectAccess.
	if ident.IsAPIKey && findingProjectID != ident.ProjectID {
		return ErrProjectAccessDenied
	}
	return nil
}
