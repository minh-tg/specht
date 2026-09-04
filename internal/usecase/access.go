package usecase

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/xMinhx/specht/internal/auth"
	"github.com/xMinhx/specht/internal/db/sqlc"
)

var ErrProjectAccessDenied = errors.New("project access denied")

func (u *Usecases) findingWithProjectAccess(ctx context.Context, findingID uuid.UUID) (sqlc.Finding, error) {
	if u.deps.Repos == nil || u.deps.Repos.Findings == nil {
		return sqlc.Finding{}, fmt.Errorf("check finding project: finding repository unavailable")
	}

	finding, err := u.deps.Repos.Findings.GetByID(ctx, pgtype.UUID{Bytes: findingID, Valid: true})
	if err != nil {
		return sqlc.Finding{}, ErrFindingNotFound
	}
	if err := checkFindingProjectIDAccess(ctx, finding.ProjectID); err != nil {
		return sqlc.Finding{}, err
	}
	return finding, nil
}

func (u *Usecases) checkFindingProjectAccess(ctx context.Context, findingID uuid.UUID) error {
	ident := auth.ContextIdentity(ctx)
	if ident == nil || !ident.IsAPIKey {
		return nil
	}

	_, err := u.findingWithProjectAccess(ctx, findingID)
	return err
}

func checkFindingRowsProjectAccess(ctx context.Context, findings []sqlc.Finding) error {
	projectID, isAPIKey, err := apiKeyProjectID(ctx)
	if err != nil || !isAPIKey {
		return err
	}

	for _, finding := range findings {
		if !finding.ProjectID.Valid || uuid.UUID(finding.ProjectID.Bytes) != projectID {
			return ErrProjectAccessDenied
		}
	}
	return nil
}

func checkFindingProjectIDAccess(ctx context.Context, findingProjectID pgtype.UUID) error {
	projectID, isAPIKey, err := apiKeyProjectID(ctx)
	if err != nil || !isAPIKey {
		return err
	}
	if !findingProjectID.Valid || uuid.UUID(findingProjectID.Bytes) != projectID {
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
