package usecase

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/xMinhx/specht/internal/auth"
	"github.com/xMinhx/specht/internal/repo"
)

// ReachabilityState values accepted by UpsertReachability.
const (
	ReachabilityReachable     = "reachable"
	ReachabilityNotReachable  = "not_reachable"
	ReachabilityUnknown       = "unknown"
	ReachabilityNotApplicable = "not_applicable"
)

// ErrInvalidReachabilityState is returned when an assessment state is not one
// of the reachability_state enum values.
var (
	ErrInvalidReachabilityState = errors.New("invalid reachability state")
	ErrProjectAccessDenied      = errors.New("project access denied")
)

func validReachabilityState(s string) bool {
	switch s {
	case ReachabilityReachable, ReachabilityNotReachable, ReachabilityUnknown, ReachabilityNotApplicable:
		return true
	}
	return false
}

// ReachabilityResponse is a finding's reachability assessment.
type ReachabilityResponse struct {
	ID         string `json:"id"`
	FindingID  string `json:"finding_id"`
	State      string `json:"state"`
	Evidence   string `json:"evidence"`
	AssessedBy string `json:"assessed_by"`
	CreatedAt  string `json:"created_at"`
}

func (u *Usecases) UpsertReachability(ctx context.Context, findingID, userID, state, evidence string) (*ReachabilityResponse, error) {
	if !validReachabilityState(state) {
		return nil, ErrInvalidReachabilityState
	}
	fid, err := uuid.Parse(findingID)
	if err != nil {
		return nil, fmt.Errorf("invalid finding id: %w", err)
	}
	uid, err := uuid.Parse(userID)
	if err != nil {
		return nil, fmt.Errorf("invalid user id: %w", err)
	}
	if err := u.checkFindingProjectAccess(ctx, fid); err != nil {
		return nil, err
	}

	r, err := u.deps.Repos.Reachability.Upsert(ctx, repo.UpsertReachabilityParams{
		FindingID:  pgtype.UUID{Bytes: fid, Valid: true},
		State:      state,
		Evidence:   evidence,
		AssessedBy: pgtype.UUID{Bytes: uid, Valid: true},
	})
	if err != nil {
		return nil, fmt.Errorf("upsert reachability: %w", err)
	}

	return &ReachabilityResponse{
		ID:         uuid.UUID(r.ID.Bytes).String(),
		FindingID:  uuid.UUID(r.FindingID.Bytes).String(),
		State:      string(r.State),
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
	if err := u.checkFindingProjectAccess(ctx, fid); err != nil {
		return nil, err
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
			State:      string(r.State),
			Evidence:   r.Evidence,
			AssessedBy: uuid.UUID(r.AssessedBy.Bytes).String(),
			CreatedAt:  r.CreatedAt.Time.Format(time.RFC3339),
		}
	}
	return result, nil
}

func (u *Usecases) checkFindingProjectAccess(ctx context.Context, findingID uuid.UUID) error {
	ident := auth.ContextIdentity(ctx)
	if ident == nil || !ident.IsAPIKey {
		return nil
	}
	project, err := uuid.Parse(ident.ProjectID)
	if err != nil {
		return ErrProjectAccessDenied
	}
	if u.deps.Repos == nil || u.deps.Repos.Findings == nil {
		return fmt.Errorf("check finding project: finding repository unavailable")
	}
	finding, err := u.deps.Repos.Findings.GetByID(ctx, pgtype.UUID{Bytes: findingID, Valid: true})
	if err != nil {
		return ErrFindingNotFound
	}
	if !finding.ProjectID.Valid || uuid.UUID(finding.ProjectID.Bytes) != project {
		return ErrProjectAccessDenied
	}
	return nil
}
