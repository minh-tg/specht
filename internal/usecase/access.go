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
		// Preserve the public not-found behavior of this helper: callers
		// should not learn persistence details from an access check.
		return port.Finding{}, ErrFindingNotFound
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
	ident := auth.ContextIdentity(ctx)
	if ident == nil || !ident.IsAPIKey {
		return nil
	}
	for _, finding := range findings {
		if finding.ProjectID != ident.ProjectID {
			return ErrProjectAccessDenied
		}
	}
	return nil
}

func checkFindingProjectIDAccess(ctx context.Context, findingProjectID string) error {
	ident := auth.ContextIdentity(ctx)
	if ident == nil || !ident.IsAPIKey {
		return nil
	}
	if findingProjectID != ident.ProjectID {
		return ErrProjectAccessDenied
	}
	return nil
}

func apiKeyProjectID(ctx context.Context) (uuid.UUID, bool, error) {
	ident := auth.ContextIdentity(ctx)
	if ident == nil || !ident.IsAPIKey {
		return uuid.Nil, false, nil
	}

	projectID, err := uuid.Parse(ident.ProjectID)
	if err != nil {
		return uuid.Nil, true, ErrProjectAccessDenied
	}
	return projectID, true, nil
}
