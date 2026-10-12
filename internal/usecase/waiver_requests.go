package usecase

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
)

// Waiver review states. Only an approved waiver counts in the gate.
const (
	WaiverStatusPending   = "pending"
	WaiverStatusApproved  = "approved"
	WaiverStatusRejected  = "rejected"
	WaiverStatusWithdrawn = "withdrawn"
)

const (
	// maxWaiverRequestAge caps how far ahead a member's request may expire.
	maxWaiverRequestAge = 90 * 24 * time.Hour
	// maxWaiverReasonLen bounds the justification text.
	maxWaiverReasonLen = 1000
	// maxWaiverRequestTargets bounds the findings one request may name.
	maxWaiverRequestTargets = 50
	// maxWaiverNameLen bounds the generated request name.
	maxWaiverNameLen = 120
)

var (
	// ErrInvalidWaiverRequest wraps validation failures on waiver input.
	// Handlers map it to a 400 and show the message.
	ErrInvalidWaiverRequest = errors.New("invalid waiver request")
	// ErrWaiverScopeRequired is returned when a waiver has no scope and does
	// not state that it covers everything.
	ErrWaiverScopeRequired = errors.New("a waiver needs a scope, or an explicit scope of all")
	// ErrWaiverNotPending is returned when a decision targets a waiver that
	// already has a final status.
	ErrWaiverNotPending = port.ErrWaiverNotPending
	// ErrWaiverExpired is returned when a request is approved after its expiry.
	ErrWaiverExpired = errors.New("waiver expired before a decision")
	// ErrWaiverSelfApproval is returned when a requester approves their own request.
	ErrWaiverSelfApproval = errors.New("a waiver request needs a second person to approve it")
	// ErrWaiverRequestExists is returned when a pending request already
	// names one of the findings.
	ErrWaiverRequestExists = errors.New("a pending waiver request already covers one of these findings")
)

// waiverRequestError carries a user-facing validation message and matches
// ErrInvalidWaiverRequest.
type waiverRequestError struct{ message string }

func (e *waiverRequestError) Error() string        { return e.message }
func (e *waiverRequestError) Is(target error) bool { return target == ErrInvalidWaiverRequest }

func invalidWaiverRequest(format string, args ...any) error {
	return &waiverRequestError{message: fmt.Sprintf(format, args...)}
}

// validateWaiverScope enforces that a waiver either names a scope or states
// that it covers every finding, never both and never neither.
func validateWaiverScope(scopeAll bool, scopeRows int) error {
	switch {
	case scopeAll && scopeRows > 0:
		return invalidWaiverRequest("scope all cannot be combined with conditions, contexts or targets")
	case !scopeAll && scopeRows == 0:
		return ErrWaiverScopeRequired
	}
	return nil
}

// validateWaiverUpdateScope applies the same rule to the scope a waiver ends
// up with after an update. Child sets the update leaves untouched count as
// they are stored.
func (u *Usecases) validateWaiverUpdateScope(ctx context.Context, waiverID string, input UpdateWaiverInput) error {
	if input.Conditions == nil && input.Contexts == nil && input.TargetIDs == nil && !input.ScopeAll {
		return nil
	}
	rows := 0
	count := func(provided bool, n int, load func() (int, error)) error {
		if provided {
			rows += n
			return nil
		}
		stored, err := load()
		if err != nil {
			return err
		}
		rows += stored
		return nil
	}
	store := u.deps.Stores.Waivers
	if err := count(input.Conditions != nil, len(input.Conditions), func() (int, error) {
		c, err := store.ListConditions(ctx, waiverID)
		return len(c), err
	}); err != nil {
		return fmt.Errorf("list conditions: %w", err)
	}
	if err := count(input.Contexts != nil, len(input.Contexts), func() (int, error) {
		c, err := store.ListContexts(ctx, waiverID)
		return len(c), err
	}); err != nil {
		return fmt.Errorf("list contexts: %w", err)
	}
	if err := count(input.TargetIDs != nil, len(input.TargetIDs), func() (int, error) {
		t, err := store.ListFindingTargets(ctx, waiverID)
		return len(t), err
	}); err != nil {
		return fmt.Errorf("list finding targets: %w", err)
	}
	return validateWaiverScope(input.ScopeAll, rows)
}

// RequestWaiverInput is a member's request to waive specific findings.
type RequestWaiverInput struct {
	ProjectSlug string
	TargetIDs   []string
	Reason      string
	ExpiresAt   *time.Time
}

// waiverRequesterRole reports whether a project role may ask for a waiver.
func waiverRequesterRole(role string) bool {
	switch role {
	case auth.RoleAdmin, auth.RoleManager, auth.RoleEditor, auth.RoleMember:
		return true
	}
	return false
}

// waiverApproverRole reports whether a project role may decide on requests.
func waiverApproverRole(role string) bool {
	switch role {
	case auth.RoleAdmin, auth.RoleManager, auth.RoleEditor:
		return true
	}
	return false
}

// RequestWaiver files a pending waiver request for specific findings. It is
// open to project members. The request never changes the gate until a
// manager or admin approves it.
func (u *Usecases) RequestWaiver(ctx context.Context, input RequestWaiverInput) (*WaiverResponse, error) {
	project, err := u.deps.Stores.Projects.GetBySlug(ctx, input.ProjectSlug)
	if err != nil {
		return nil, fmt.Errorf(errLookupProjectFormat, input.ProjectSlug, err)
	}
	role, err := u.callerProjectRole(ctx, project.ID)
	if err != nil {
		return nil, err
	}
	if !waiverRequesterRole(role) {
		return nil, ErrProjectAccessDenied
	}
	ident := auth.ContextIdentity(ctx)

	reason := strings.TrimSpace(input.Reason)
	if reason == "" {
		return nil, invalidWaiverRequest("reason is required")
	}
	if len([]rune(reason)) > maxWaiverReasonLen {
		return nil, invalidWaiverRequest("reason is longer than %d characters", maxWaiverReasonLen)
	}
	requestedAt := now()
	if input.ExpiresAt == nil {
		return nil, invalidWaiverRequest("expires_at is required")
	}
	if !input.ExpiresAt.After(requestedAt) {
		return nil, invalidWaiverRequest("expires_at must be in the future")
	}
	if input.ExpiresAt.After(requestedAt.Add(maxWaiverRequestAge)) {
		return nil, invalidWaiverRequest("expires_at is more than %d days ahead", int(maxWaiverRequestAge/(24*time.Hour)))
	}
	if len(input.TargetIDs) == 0 {
		return nil, invalidWaiverRequest("target_ids needs at least one finding")
	}
	if len(input.TargetIDs) > maxWaiverRequestTargets {
		return nil, invalidWaiverRequest("target_ids is longer than %d findings", maxWaiverRequestTargets)
	}

	targets := make([]port.WaiverFindingTarget, 0, len(input.TargetIDs))
	seen := make(map[string]bool, len(input.TargetIDs))
	var firstTitle string
	for _, raw := range input.TargetIDs {
		id, err := uuid.Parse(raw)
		if err != nil {
			return nil, invalidWaiverRequest("invalid finding id %q", raw)
		}
		if seen[id.String()] {
			continue
		}
		seen[id.String()] = true
		finding, err := u.deps.Stores.Findings.GetByID(ctx, id.String())
		if err != nil || finding.ProjectID != project.ID {
			if err != nil && !errors.Is(err, port.ErrNotFound) {
				return nil, fmt.Errorf("get finding: %w", err)
			}
			return nil, invalidWaiverRequest("finding %s was not found in this project", id)
		}
		if firstTitle == "" {
			firstTitle = finding.CurrentTitle
		}
		targets = append(targets, port.WaiverFindingTarget{FindingID: id.String()})
	}

	if err := u.rejectDuplicateWaiverRequest(ctx, project.ID, seen); err != nil {
		return nil, err
	}

	metadata, err := json.Marshal(map[string]any{"reason": reason})
	if err != nil {
		return nil, fmt.Errorf("marshal waiver event metadata: %w", err)
	}
	w, err := u.deps.Stores.Waivers.CreateWithDetails(ctx, port.CreateWaiverInput{
		ProjectID:   project.ID,
		Name:        waiverRequestName(firstTitle, len(targets)),
		Enabled:     true,
		ExpiresAt:   input.ExpiresAt,
		Status:      WaiverStatusPending,
		Reason:      reason,
		RequestedBy: &ident.UserID,
		RequestedAt: &requestedAt,
		Targets:     targets,
		Event: port.WaiverEventInput{
			EventType: "requested",
			ActorID:   &ident.UserID,
			Metadata:  metadata,
		},
	})
	if err != nil {
		return nil, err
	}
	resp := toWaiver(w)
	return &resp, nil
}

// rejectDuplicateWaiverRequest refuses a request that names a finding another
// pending request already names, so a double click or a second teammate does
// not stack requests.
func (u *Usecases) rejectDuplicateWaiverRequest(ctx context.Context, projectID string, findingIDs map[string]bool) error {
	waivers, err := u.deps.Stores.Waivers.List(ctx, projectID)
	if err != nil {
		return fmt.Errorf("list waivers: %w", err)
	}
	var pending []string
	for _, w := range waivers {
		if w.Status == WaiverStatusPending {
			pending = append(pending, w.ID)
		}
	}
	if len(pending) == 0 {
		return nil
	}
	targets, err := u.deps.Stores.Waivers.ListFindingTargetsByWaiverIDs(ctx, pending)
	if err != nil {
		return fmt.Errorf("list waiver finding targets: %w", err)
	}
	for _, t := range targets {
		if findingIDs[t.FindingID] {
			return ErrWaiverRequestExists
		}
	}
	return nil
}

// waiverRequestName builds the stored name of a request from the first
// finding's title.
func waiverRequestName(title string, targets int) string {
	name := "Waiver request"
	if title = strings.TrimSpace(title); title != "" {
		name += ": " + title
	}
	if r := []rune(name); len(r) > maxWaiverNameLen {
		name = string(r[:maxWaiverNameLen-1]) + "…"
	}
	if targets > 1 {
		name += fmt.Sprintf(" (+%d more)", targets-1)
	}
	return name
}

// ApproveWaiver approves a pending request. The requester cannot approve
// their own request, except a global admin, who would otherwise lock out a
// one-person project; that approval is marked in the event.
func (u *Usecases) ApproveWaiver(ctx context.Context, projectSlug, waiverID, note string) (*WaiverResponse, error) {
	return u.decideWaiver(ctx, projectSlug, waiverID, WaiverStatusApproved, strings.TrimSpace(note))
}

// RejectWaiver rejects a pending request. A note is required so the
// requester learns why.
func (u *Usecases) RejectWaiver(ctx context.Context, projectSlug, waiverID, note string) (*WaiverResponse, error) {
	note = strings.TrimSpace(note)
	if note == "" {
		return nil, invalidWaiverRequest("note is required when rejecting a request")
	}
	return u.decideWaiver(ctx, projectSlug, waiverID, WaiverStatusRejected, note)
}

// WithdrawWaiver lets the requester take back a pending request.
func (u *Usecases) WithdrawWaiver(ctx context.Context, projectSlug, waiverID string) (*WaiverResponse, error) {
	return u.decideWaiver(ctx, projectSlug, waiverID, WaiverStatusWithdrawn, "")
}

var waiverDecisionEvents = map[string]string{
	WaiverStatusApproved:  "approved",
	WaiverStatusRejected:  "rejected",
	WaiverStatusWithdrawn: "withdrawn",
}

func (u *Usecases) decideWaiver(ctx context.Context, projectSlug, waiverID, status, note string) (*WaiverResponse, error) {
	project, err := u.deps.Stores.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return nil, fmt.Errorf(errLookupProjectFormat, projectSlug, err)
	}
	role, err := u.callerProjectRole(ctx, project.ID)
	if err != nil {
		return nil, err
	}
	ident := auth.ContextIdentity(ctx)

	id, err := uuid.Parse(waiverID)
	if err != nil {
		return nil, fmt.Errorf(errInvalidWaiverIDFormat, err)
	}
	waiver, err := u.deps.Stores.Waivers.GetByID(ctx, id.String(), project.ID)
	if err != nil {
		return nil, fmt.Errorf("get waiver: %w", err)
	}

	isRequester := waiver.RequestedBy != nil && *waiver.RequestedBy == ident.UserID
	selfApproved := false
	switch status {
	case WaiverStatusWithdrawn:
		if !isRequester {
			return nil, ErrProjectAccessDenied
		}
	default:
		if !waiverApproverRole(role) {
			return nil, ErrProjectAccessDenied
		}
		if status == WaiverStatusApproved && isRequester {
			if ident.Role != auth.RoleAdmin {
				return nil, ErrWaiverSelfApproval
			}
			selfApproved = true
		}
	}
	if waiver.Status != WaiverStatusPending {
		return nil, ErrWaiverNotPending
	}
	if status == WaiverStatusApproved && waiver.ExpiresAt != nil && !waiver.ExpiresAt.After(now()) {
		return nil, ErrWaiverExpired
	}

	metadata, err := json.Marshal(map[string]any{"note": note, "self_approved": selfApproved})
	if err != nil {
		return nil, fmt.Errorf("marshal waiver event metadata: %w", err)
	}
	w, err := u.deps.Stores.Waivers.Decide(ctx, id.String(), project.ID, port.WaiverDecision{
		Status:  status,
		ActorID: ident.UserID,
		Note:    note,
		Event: port.WaiverEventInput{
			EventType: waiverDecisionEvents[status],
			ActorID:   &ident.UserID,
			Metadata:  metadata,
		},
	})
	if err != nil {
		return nil, err
	}
	resp := toWaiver(w)
	return &resp, nil
}
