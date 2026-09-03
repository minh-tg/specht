package usecase

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/xMinhx/specht/internal/repo"
)

// ReachabilityResponse is a finding's reachability assessment.
type ReachabilityResponse struct {
	ID         string `json:"id"`
	FindingID  string `json:"finding_id"`
	Reachable  bool   `json:"reachable"`
	Evidence   string `json:"evidence"`
	AssessedBy string `json:"assessed_by"`
	CreatedAt  string `json:"created_at"`
}

func (u *Usecases) UpsertReachability(ctx context.Context, findingID, userID string, reachable bool, evidence string) (*ReachabilityResponse, error) {
	fid, err := uuid.Parse(findingID)
	if err != nil {
		return nil, fmt.Errorf("invalid finding id: %w", err)
	}
	uid, err := uuid.Parse(userID)
	if err != nil {
		return nil, fmt.Errorf("invalid user id: %w", err)
	}

	r, err := u.deps.Repos.Reachability.Upsert(ctx, repo.UpsertReachabilityParams{
		FindingID:  pgtype.UUID{Bytes: fid, Valid: true},
		Reachable:  reachable,
		Evidence:   evidence,
		AssessedBy: pgtype.UUID{Bytes: uid, Valid: true},
	})
	if err != nil {
		return nil, fmt.Errorf("upsert reachability: %w", err)
	}

	return &ReachabilityResponse{
		ID:         uuid.UUID(r.ID.Bytes).String(),
		FindingID:  uuid.UUID(r.FindingID.Bytes).String(),
		Reachable:  r.Reachable,
		Evidence:   r.Evidence,
		AssessedBy: uuid.UUID(r.AssessedBy.Bytes).String(),
		CreatedAt:  r.CreatedAt.Time.Format(time.RFC3339),
	}, nil
}

func (u *Usecases) ListReachability(ctx context.Context, findingID string) ([]ReachabilityResponse, error) {
	fid, err := uuid.Parse(findingID)
	if err != nil {
		return nil, fmt.Errorf("invalid finding id: %w", err)
	}

	rows, err := u.deps.Repos.Reachability.ListByFinding(ctx, pgtype.UUID{Bytes: fid, Valid: true})
	if err != nil {
		return nil, fmt.Errorf("list reachability: %w", err)
	}

	result := make([]ReachabilityResponse, len(rows))
	for i, r := range rows {
		result[i] = ReachabilityResponse{
			ID:         uuid.UUID(r.ID.Bytes).String(),
			FindingID:  uuid.UUID(r.FindingID.Bytes).String(),
			Reachable:  r.Reachable,
			Evidence:   r.Evidence,
			AssessedBy: uuid.UUID(r.AssessedBy.Bytes).String(),
			CreatedAt:  r.CreatedAt.Time.Format(time.RFC3339),
		}
	}
	return result, nil
}
