package usecase

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/minh-tg/specht/internal/port"
)

// SignoffResponse is a signoff record attached to a finding.
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
	if err := u.checkFindingProjectEditor(ctx, fid); err != nil {
		return nil, err
	}

	s, err := u.deps.Stores.Signoffs.Upsert(ctx, fid.String(), status, uid.String(), comment)
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
	if err := u.checkFindingProjectAccess(ctx, fid); err != nil {
		return nil, err
	}

	s, err := u.deps.Stores.Signoffs.GetByFinding(ctx, fid.String())
	if err != nil {
		return nil, fmt.Errorf("get signoff: %w", err)
	}

	return signoffToResponse(s), nil
}

func signoffToResponse(s port.Signoff) *SignoffResponse {
	return &SignoffResponse{
		ID:         s.ID,
		FindingID:  s.FindingID,
		Status:     s.Status,
		ReviewedBy: s.ReviewedBy,
		Comment:    s.Comment,
		CreatedAt:  s.CreatedAt.Format(time.RFC3339),
		UpdatedAt:  s.UpdatedAt.Format(time.RFC3339),
	}
}
