package usecase

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/xMinhx/specht/internal/db/sqlc"
	"github.com/xMinhx/specht/internal/repo"
)

func (u *Usecases) CreateEvidence(ctx context.Context, findingID, userID string, typ, url, description string) (sqlc.EvidenceArtifact, error) {
	fid, err := uuid.Parse(findingID)
	if err != nil {
		return sqlc.EvidenceArtifact{}, fmt.Errorf("invalid finding id: %w", err)
	}

	var uploadedBy pgtype.UUID
	if userID != "" {
		uid, err := uuid.Parse(userID)
		if err == nil {
			uploadedBy = pgtype.UUID{Bytes: uid, Valid: true}
		}
	}

	return u.deps.Repos.Evidence.Create(ctx, repo.CreateEvidenceParams{
		FindingID:   pgtype.UUID{Bytes: fid, Valid: true},
		Type:        typ,
		URL:         url,
		Description: description,
		UploadedBy:  uploadedBy,
	})
}

func (u *Usecases) ListEvidence(ctx context.Context, findingID string) ([]sqlc.EvidenceArtifact, error) {
	fid, err := uuid.Parse(findingID)
	if err != nil {
		return nil, fmt.Errorf("invalid finding id: %w", err)
	}
	return u.deps.Repos.Evidence.ListByFinding(ctx, pgtype.UUID{Bytes: fid, Valid: true})
}

func (u *Usecases) DeleteEvidence(ctx context.Context, evidenceID string) error {
	eid, err := uuid.Parse(evidenceID)
	if err != nil {
		return fmt.Errorf("invalid evidence id: %w", err)
	}
	return u.deps.Repos.Evidence.Delete(ctx, pgtype.UUID{Bytes: eid, Valid: true})
}
