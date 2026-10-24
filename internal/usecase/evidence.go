package usecase

import (
	"context"
	"errors"
	"fmt"
	urlpkg "net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/minh-tg/specht/internal/port"
)

// ErrEvidenceNotFound is returned when the evidence row does not exist.
// Handlers map it to a 404.
var ErrEvidenceNotFound = errors.New("evidence not found")

// ErrInvalidEvidenceURL is returned for an evidence link that is not an
// absolute http or https URL. Handlers map it to a 422.
var ErrInvalidEvidenceURL = errors.New("evidence URL must be an absolute http or https URL")

// ErrInvalidEvidenceType is returned when the evidence type is outside the
// persistence vocabulary. Handlers map it to a 400.
var ErrInvalidEvidenceType = errors.New("invalid evidence type")

// evidenceTypes is the allowed evidence type vocabulary (migration 000013
// CHECK constraint). CreateEvidence rejects anything else at the boundary
// instead of letting the driver error surface as a 500.
var evidenceTypes = map[string]bool{
	"screenshot": true,
	"log":        true,
	"reference":  true,
	"automated":  true,
}

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
		return EvidenceResponse{}, fmt.Errorf("%w: %v", ErrInvalidFindingID, err)
	}
	if err := u.checkFindingProjectEditor(ctx, fid); err != nil {
		return EvidenceResponse{}, err
	}
	if !evidenceTypes[typ] {
		return EvidenceResponse{}, ErrInvalidEvidenceType
	}
	url = strings.TrimSpace(url)
	parsed, err := urlpkg.Parse(url)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return EvidenceResponse{}, ErrInvalidEvidenceURL
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
		return nil, fmt.Errorf("%w: %v", ErrInvalidFindingID, err)
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

// DeleteEvidence removes one evidence artifact addressed through its own
// finding. The finding in the path is the authorization anchor and must exist,
// and the evidence must belong to it. A missing finding, a missing evidence id
// and a mismatched pair all answer ErrEvidenceNotFound (404 not_found) so
// neither kind of id can be probed, and the pair check runs after the access
// check so a caller without write access is refused with 403, not 404.
func (u *Usecases) DeleteEvidence(ctx context.Context, findingID, evidenceID string) error {
	fid, err := uuid.Parse(findingID)
	if err != nil {
		return ErrInvalidID
	}
	eid, err := uuid.Parse(evidenceID)
	if err != nil {
		return ErrInvalidID
	}

	// Resolve the finding in the path and enforce the caller's project scope
	// for every authenticated identity, not just API keys: the access checks
	// fail closed, so an identity without a matching project scope is denied
	// before the evidence is read or deleted.
	if err := u.checkFindingProjectEditor(ctx, fid); err != nil {
		return err
	}

	evidence, err := u.deps.Stores.Evidence.GetByID(ctx, eid.String())
	if err != nil {
		if errors.Is(err, port.ErrNotFound) {
			return ErrEvidenceNotFound
		}
		return fmt.Errorf("get evidence: %w", err)
	}
	if evidence.FindingID != fid.String() {
		return ErrEvidenceNotFound
	}
	return u.deps.Stores.Evidence.Delete(ctx, eid.String())
}
