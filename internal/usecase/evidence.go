package usecase

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/minh-tg/specht/internal/port"
)

// EvidenceResponse is an evidence artifact attached to a finding.
type EvidenceResponse struct {
	ID          string  `json:"id"`
	FindingID   string  `json:"finding_id"`
	Type        string  `json:"type"`
	URL         string  `json:"url"`
	Description string  `json:"description"`
	UploadedBy  *string `json:"uploaded_by"`
	CreatedAt   string  `json:"created_at"`
}

func (u *Usecases) CreateEvidence(ctx context.Context, findingID, userID string, typ, url, description string) (EvidenceResponse, error) {
	fid, err := uuid.Parse(findingID)
	if err != nil {
		return EvidenceResponse{}, fmt.Errorf("invalid finding id: %w", err)
	}
	if err := u.checkFindingProjectAccess(ctx, fid); err != nil {
		return EvidenceResponse{}, err
	}

	var uploadedBy *string
	if userID != "" {
		uid, err := uuid.Parse(userID)
		if err == nil {
			normalized := uid.String()
			uploadedBy = &normalized
		}
	}

	evidence, err := u.deps.Stores.Evidence.Create(ctx, port.EvidenceInput{
		FindingID:   fid.String(),
		Type:        typ,
		URL:         url,
		Description: description,
		UploadedBy:  uploadedBy,
	})
	if err != nil {
		return EvidenceResponse{}, err
	}
	return evidenceToResponse(evidence), nil
}

func evidenceToResponse(e port.Evidence) EvidenceResponse {
	return EvidenceResponse{
		ID:          e.ID,
		FindingID:   e.FindingID,
		Type:        e.Type,
		URL:         e.URL,
		Description: e.Description,
		UploadedBy:  e.UploadedBy,
		CreatedAt:   e.CreatedAt.Format(time.RFC3339Nano),
	}
}

func (u *Usecases) ListEvidence(ctx context.Context, findingID string) ([]EvidenceResponse, error) {
	fid, err := uuid.Parse(findingID)
	if err != nil {
		return nil, fmt.Errorf("invalid finding id: %w", err)
	}
	if err := u.checkFindingProjectAccess(ctx, fid); err != nil {
		return nil, err
	}
	evidence, err := u.deps.Stores.Evidence.ListByFinding(ctx, fid.String())
	if err != nil {
		return nil, err
	}
	result := make([]EvidenceResponse, len(evidence))
	for i, e := range evidence {
		result[i] = evidenceToResponse(e)
	}
	return result, nil
}

func (u *Usecases) DeleteEvidence(ctx context.Context, evidenceID string) error {
	eid, err := uuid.Parse(evidenceID)
	if err != nil {
		return fmt.Errorf("invalid evidence id: %w", err)
	}
	// Resolve the evidence to its finding and enforce the caller's project
	// scope for every authenticated identity, not just API keys: the access
	// checks fail closed, so an identity without a matching project scope is
	// denied before the delete.
	evidence, err := u.deps.Stores.Evidence.GetByID(ctx, eid.String())
	if err != nil {
		return fmt.Errorf("get evidence: %w", err)
	}
	fid, err := uuid.Parse(evidence.FindingID)
	if err != nil {
		return fmt.Errorf("evidence finding id is invalid")
	}
	if err := u.checkFindingProjectAccess(ctx, fid); err != nil {
		return err
	}
	return u.deps.Stores.Evidence.Delete(ctx, eid.String())
}
