package usecase

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/xMinhx/specht/internal/db/sqlc"
	"github.com/xMinhx/specht/internal/repo"
)

type SignoffResponse struct {
	ID         string `json:"id"`
	FindingID  string `json:"finding_id"`
	Status     string `json:"status"`
	ReviewedBy string `json:"reviewed_by"`
	Comment    string `json:"comment"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
}

func (u *Usecases) UpsertSignoff(ctx context.Context, findingID, userID, status, comment string) (*SignoffResponse, error) {
	fid, err := uuid.Parse(findingID)
	if err != nil {
		return nil, fmt.Errorf("invalid finding id: %w", err)
	}
	uid, err := uuid.Parse(userID)
	if err != nil {
		return nil, fmt.Errorf("invalid user id: %w", err)
	}

	s, err := u.deps.Repos.Signoffs.Upsert(ctx, repo.UpsertSignoffParams{
		FindingID:  pgtype.UUID{Bytes: fid, Valid: true},
		Status:     status,
		ReviewedBy: pgtype.UUID{Bytes: uid, Valid: true},
		Comment:    comment,
	})
	if err != nil {
		return nil, fmt.Errorf("upsert signoff: %w", err)
	}

	return signoffToResponse(s), nil
}

func (u *Usecases) GetSignoff(ctx context.Context, findingID string) (*SignoffResponse, error) {
	fid, err := uuid.Parse(findingID)
	if err != nil {
		return nil, fmt.Errorf("invalid finding id: %w", err)
	}

	s, err := u.deps.Repos.Signoffs.GetByFinding(ctx, pgtype.UUID{Bytes: fid, Valid: true})
	if err != nil {
		return nil, fmt.Errorf("get signoff: %w", err)
	}

	return signoffToResponse(s), nil
}

func signoffToResponse(s sqlc.Signoff) *SignoffResponse {
	return &SignoffResponse{
		ID:         uuid.UUID(s.ID.Bytes).String(),
		FindingID:  uuid.UUID(s.FindingID.Bytes).String(),
		Status:     string(s.Status),
		ReviewedBy: uuid.UUID(s.ReviewedBy.Bytes).String(),
		Comment:    s.Comment,
		CreatedAt:  s.CreatedAt.Time.Format(time.RFC3339),
		UpdatedAt:  s.UpdatedAt.Time.Format(time.RFC3339),
	}
}
