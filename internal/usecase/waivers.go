package usecase

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/gate"
	"github.com/minh-tg/specht/internal/port"
)

// errInvalidWaiverIDFormat wraps waiver-id parse failures.
const errInvalidWaiverIDFormat = "invalid waiver id: %w"

// WaiverResponse is the API representation of a waiver with its condition,
// context, and target rows attached.
type WaiverResponse struct {
	ID          string `json:"id"`
	ProjectID   string `json:"project_id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
	// Status is the review state: pending, approved, rejected or withdrawn.
	// Only approved waivers count in the gate.
	Status string `json:"status"`
	// ScopeAll marks a waiver that covers every finding of the project.
	ScopeAll    bool    `json:"scope_all"`
	Reason      string  `json:"reason"`
	RequestedBy *string `json:"requested_by,omitempty"`
	// RequestedByName and DecidedByName say who those ids are, for people reading a
	// project's waivers. They are left out for API keys.
	RequestedByName string                    `json:"requested_by_name,omitempty"`
	DecidedByName   string                    `json:"decided_by_name,omitempty"`
	RequestedAt     *string                   `json:"requested_at,omitempty"`
	DecidedBy       *string                   `json:"decided_by,omitempty"`
	DecidedAt       *string                   `json:"decided_at,omitempty"`
	DecisionNote    string                    `json:"decision_note"`
	ExpiresAt       *string                   `json:"expires_at,omitempty"`
	Conditions      []WaiverConditionResp     `json:"conditions"`
	Contexts        []WaiverContextResp       `json:"contexts"`
	Targets         []WaiverFindingTargetResp `json:"targets"`
	CreatedAt       string                    `json:"created_at"`
	UpdatedAt       string                    `json:"updated_at"`
}

// WaiverConditionResp is a waiver condition in API responses.
type WaiverConditionResp struct {
	ID       string `json:"id"`
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
}

// WaiverContextResp is a waiver context scope in API responses.
type WaiverContextResp struct {
	ID            string `json:"id"`
	EnvironmentID string `json:"environment_id,omitempty"`
	TargetID      string `json:"target_id,omitempty"`
	ArtifactID    string `json:"artifact_id,omitempty"`
}

// WaiverFindingTargetResp is a waiver finding target in API responses.
type WaiverFindingTargetResp struct {
	ID        string `json:"id"`
	FindingID string `json:"finding_id"`
}

// WaiverEventResp is a waiver audit event in API responses.
type WaiverEventResp struct {
	ID        string          `json:"id"`
	WaiverID  string          `json:"waiver_id"`
	EventType string          `json:"event_type"`
	ActorID   string          `json:"actor_id,omitempty"`
	ActorName string          `json:"actor_name,omitempty"`
	Metadata  json.RawMessage `json:"metadata,omitempty"`
	CreatedAt string          `json:"created_at"`
}

// CreateWaiverInput is a request to create a waiver: a name/description plus
// optional conditions, deployment-context scopes, and directly-targeted
// finding ids. A waiver that covers every blocking finding in the project has
// to say so with ScopeAll and no other scope; an empty scope without ScopeAll
// is rejected.
type CreateWaiverInput struct {
	ProjectSlug string
	Name        string
	Description string
	// ExpiresAt optionally bounds the waiver (RFC3339 at the API edge);
	// nil creates a waiver that never expires.
	ExpiresAt  *time.Time
	ScopeAll   bool
	Conditions []CreateWaiverConditionInput
	Contexts   []CreateWaiverContextInput
	TargetIDs  []string
	ActorID    string
}

// CreateWaiverConditionInput is a condition input for waiver create/update.
type CreateWaiverConditionInput struct {
	Field    string
	Operator string
	Value    string
}

// CreateWaiverContextInput is a context scope input for waiver create/update.
type CreateWaiverContextInput struct {
	EnvironmentID string `json:"environment_id"`
	TargetID      string `json:"target_id"`
	ArtifactID    string `json:"artifact_id"`
}

// UpdateWaiverInput is a request to update a waiver. Name and Description
// replace the stored values when non-empty; a non-nil Conditions/Contexts/
// TargetIDs slice replaces that child set (nil leaves it untouched).
type UpdateWaiverInput struct {
	WaiverID    string
	ProjectSlug string
	Name        string
	Description string
	// ExpiresAt sets a new expiry; ClearExpiresAt writes NULL; both absent
	// leaves the stored expiry untouched.
	ExpiresAt      *time.Time
	ClearExpiresAt bool
	// ScopeAll states that the waiver should cover every finding; it needs
	// an empty scope after the update.
	ScopeAll   bool
	Conditions []CreateWaiverConditionInput
	Contexts   []CreateWaiverContextInput
	TargetIDs  []string
	ActorID    string
}

// WaiverDetailResponse is a waiver with full condition/context/target rows.
type WaiverDetailResponse struct {
	WaiverResponse
	Conditions []WaiverConditionResp     `json:"conditions"`
	Contexts   []WaiverContextResp       `json:"contexts"`
	Targets    []WaiverFindingTargetResp `json:"targets"`
}

func toWaiver(w port.Waiver) WaiverResponse {
	var expiresAt *string
	if w.ExpiresAt != nil {
		s := w.ExpiresAt.Format(time.RFC3339)
		expiresAt = &s
	}
	return WaiverResponse{
		ID:           w.ID,
		ProjectID:    w.ProjectID,
		Name:         w.Name,
		Description:  w.Description,
		Enabled:      w.Enabled,
		Status:       w.Status,
		ScopeAll:     w.ScopeAll,
		Reason:       w.Reason,
		RequestedBy:  w.RequestedBy,
		RequestedAt:  formatTimePtr(w.RequestedAt),
		DecidedBy:    w.DecidedBy,
		DecidedAt:    formatTimePtr(w.DecidedAt),
		DecisionNote: w.DecisionNote,
		ExpiresAt:    expiresAt,
		Conditions:   make([]WaiverConditionResp, 0),
		Contexts:     make([]WaiverContextResp, 0),
		Targets:      make([]WaiverFindingTargetResp, 0),
		CreatedAt:    w.CreatedAt.Format(time.RFC3339),
		// UpdatedAt keeps its sub-second digits: revoke and restore take it
		// back as a precondition, and a second-level value would match a
		// waiver that changed again within the same second.
		UpdatedAt: w.UpdatedAt.Format(time.RFC3339Nano),
	}
}

func formatTimePtr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := t.Format(time.RFC3339)
	return &s
}

func toWaiverCondition(c port.WaiverCondition) WaiverConditionResp {
	return WaiverConditionResp{
		ID:       c.ID,
		Field:    c.Field,
		Operator: c.Operator,
		Value:    c.Value,
	}
}

func toWaiverContext(c port.WaiverContext) WaiverContextResp {
	return WaiverContextResp{
		ID:            c.ID,
		EnvironmentID: c.EnvironmentID,
		TargetID:      c.TargetID,
		ArtifactID:    c.ArtifactID,
	}
}

func toWaiverFindingTarget(t port.WaiverFindingTarget) WaiverFindingTargetResp {
	return WaiverFindingTargetResp{
		ID:        t.ID,
		FindingID: t.FindingID,
	}
}

func toWaiverEvent(e port.WaiverEvent) WaiverEventResp {
	return WaiverEventResp{
		ID:        e.ID,
		WaiverID:  e.WaiverID,
		EventType: e.EventType,
		ActorID:   e.ActorID,
		Metadata:  e.Metadata,
		CreatedAt: e.CreatedAt.Format(time.RFC3339),
	}
}

func toWaiverDetail(w port.Waiver, conditions []port.WaiverCondition, contexts []port.WaiverContext, targets []port.WaiverFindingTarget) WaiverDetailResponse {
	resp := WaiverDetailResponse{
		WaiverResponse: toWaiver(w),
		Conditions:     make([]WaiverConditionResp, len(conditions)),
		Contexts:       make([]WaiverContextResp, len(contexts)),
		Targets:        make([]WaiverFindingTargetResp, len(targets)),
	}
	for i, c := range conditions {
		resp.Conditions[i] = toWaiverCondition(c)
	}
	for i, c := range contexts {
		resp.Contexts[i] = toWaiverContext(c)
	}
	for i, t := range targets {
		resp.Targets[i] = toWaiverFindingTarget(t)
	}
	return resp
}

var waiverCreatedEvent = []byte("{}")

func (u *Usecases) CreateWaiver(ctx context.Context, input CreateWaiverInput) (*WaiverResponse, error) {
	project, err := u.deps.Stores.Projects.GetBySlug(ctx, input.ProjectSlug)
	if err != nil {
		return nil, fmt.Errorf(errLookupProjectFormat, input.ProjectSlug, err)
	}
	if err := u.requireProjectAdminForWaiver(ctx, project.ID); err != nil {
		return nil, err
	}

	if err := validateWaiverScope(input.ScopeAll, len(input.Conditions)+len(input.Contexts)+len(input.TargetIDs)); err != nil {
		return nil, err
	}

	conditions := make([]port.WaiverCondition, len(input.Conditions))
	for i, c := range input.Conditions {
		conditions[i] = port.WaiverCondition{
			Field:    c.Field,
			Operator: c.Operator,
			Value:    c.Value,
		}
	}

	contexts, err := waiverContextInputs(input.Contexts)
	if err != nil {
		return nil, err
	}

	targets := make([]port.WaiverFindingTarget, len(input.TargetIDs))
	for i, targetID := range input.TargetIDs {
		id, err := uuid.Parse(targetID)
		if err != nil {
			return nil, invalidWaiverRequest("invalid target finding id %q", targetID)
		}
		targets[i] = port.WaiverFindingTarget{FindingID: id.String()}
	}
	if err := u.requireWaiverScopeInProject(ctx, project.ID, contexts, targets); err != nil {
		return nil, err
	}

	actorID := stringPtr(input.ActorID)
	w, err := u.deps.Stores.Waivers.CreateWithDetails(ctx, port.CreateWaiverInput{
		ProjectID:   project.ID,
		Name:        input.Name,
		Description: input.Description,
		Enabled:     true,
		ExpiresAt:   input.ExpiresAt,
		Status:      WaiverStatusApproved,
		Conditions:  conditions,
		Contexts:    contexts,
		Targets:     targets,
		Event: port.WaiverEventInput{
			EventType: "created",
			ActorID:   actorID,
			Metadata:  waiverCreatedEvent,
		},
	})
	if err != nil {
		return nil, err
	}

	r := toWaiver(w)
	return &r, nil
}

// ListWaivers returns the project's waivers, newest first, each with its
// conditions, contexts and finding targets, so a screen can tell which
// findings a pending request covers without a read per waiver. With statuses
// it keeps only waivers in one of those review states.
func (u *Usecases) ListWaivers(ctx context.Context, projectSlug string, statuses ...string) ([]WaiverResponse, error) {
	project, err := u.deps.Stores.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return nil, fmt.Errorf(errLookupProjectFormat, projectSlug, err)
	}
	if err := u.requireProjectMember(ctx, project.ID); err != nil {
		return nil, err
	}

	waivers, err := u.deps.Stores.Waivers.List(ctx, project.ID)
	if err != nil {
		return nil, fmt.Errorf("list waivers: %w", err)
	}

	kept := make([]port.Waiver, 0, len(waivers))
	ids := make([]string, 0, len(waivers))
	for _, w := range waivers {
		if len(statuses) > 0 && !slices.Contains(statuses, w.Status) {
			continue
		}
		kept = append(kept, w)
		ids = append(ids, w.ID)
	}
	resp := make([]WaiverResponse, len(kept))
	for i, w := range kept {
		resp[i] = toWaiver(w)
	}
	u.nameWaiverPeople(ctx, resp)
	if len(ids) == 0 {
		return resp, nil
	}

	conditions, err := u.deps.Stores.Waivers.ListConditionsByWaiverIDs(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("list waiver conditions: %w", err)
	}
	contexts, err := u.deps.Stores.Waivers.ListContextsByWaiverIDs(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("list waiver contexts: %w", err)
	}
	targets, err := u.deps.Stores.Waivers.ListFindingTargetsByWaiverIDs(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("list waiver finding targets: %w", err)
	}
	position := make(map[string]int, len(kept))
	for i, w := range kept {
		position[w.ID] = i
	}
	for _, c := range conditions {
		if i, ok := position[c.WaiverID]; ok {
			resp[i].Conditions = append(resp[i].Conditions, toWaiverCondition(c))
		}
	}
	for _, c := range contexts {
		if i, ok := position[c.WaiverID]; ok {
			resp[i].Contexts = append(resp[i].Contexts, toWaiverContext(c))
		}
	}
	for _, t := range targets {
		if i, ok := position[t.WaiverID]; ok {
			resp[i].Targets = append(resp[i].Targets, toWaiverFindingTarget(t))
		}
	}
	return resp, nil
}

func (u *Usecases) GetWaiver(ctx context.Context, projectSlug, waiverID string) (*WaiverDetailResponse, error) {
	project, err := u.deps.Stores.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return nil, fmt.Errorf(errLookupProjectFormat, projectSlug, err)
	}
	if err := u.requireProjectMember(ctx, project.ID); err != nil {
		return nil, err
	}

	id, err := uuid.Parse(waiverID)
	if err != nil {
		return nil, fmt.Errorf(errInvalidWaiverIDFormat, err)
	}

	w, err := u.deps.Stores.Waivers.GetByID(ctx, id.String(), project.ID)
	if err != nil {
		return nil, fmt.Errorf("get waiver: %w", err)
	}

	conditions, err := u.deps.Stores.Waivers.ListConditions(ctx, w.ID)
	if err != nil {
		return nil, fmt.Errorf("list conditions: %w", err)
	}

	contexts, err := u.deps.Stores.Waivers.ListContexts(ctx, w.ID)
	if err != nil {
		return nil, fmt.Errorf("list contexts: %w", err)
	}

	targets, err := u.deps.Stores.Waivers.ListFindingTargets(ctx, w.ID)
	if err != nil {
		return nil, fmt.Errorf("list finding targets: %w", err)
	}

	resp := toWaiverDetail(w, conditions, contexts, targets)
	named := []WaiverResponse{resp.WaiverResponse}
	u.nameWaiverPeople(ctx, named)
	resp.WaiverResponse = named[0]
	return &resp, nil
}

func (u *Usecases) UpdateWaiver(ctx context.Context, input UpdateWaiverInput) (*WaiverResponse, error) {
	project, err := u.deps.Stores.Projects.GetBySlug(ctx, input.ProjectSlug)
	if err != nil {
		return nil, fmt.Errorf(errLookupProjectFormat, input.ProjectSlug, err)
	}
	if err := u.requireProjectAdminForWaiver(ctx, project.ID); err != nil {
		return nil, err
	}

	id, err := uuid.Parse(input.WaiverID)
	if err != nil {
		return nil, fmt.Errorf(errInvalidWaiverIDFormat, err)
	}
	waiver := port.Waiver{
		ID:          id.String(),
		ProjectID:   project.ID,
		Name:        input.Name,
		Description: input.Description,
	}

	var conditions *[]port.WaiverCondition
	if input.Conditions != nil {
		conds := make([]port.WaiverCondition, len(input.Conditions))
		for i, c := range input.Conditions {
			conds[i] = port.WaiverCondition{Field: c.Field, Operator: c.Operator, Value: c.Value}
		}
		conditions = &conds
	}

	var contexts *[]port.WaiverContext
	if input.Contexts != nil {
		ctxs, err := waiverContextInputs(input.Contexts)
		if err != nil {
			return nil, err
		}
		contexts = &ctxs
	}

	var targets *[]port.WaiverFindingTarget
	if input.TargetIDs != nil {
		tgts := make([]port.WaiverFindingTarget, len(input.TargetIDs))
		for i, targetID := range input.TargetIDs {
			uid, err := uuid.Parse(targetID)
			if err != nil {
				return nil, invalidWaiverRequest("invalid target finding id %q", targetID)
			}
			tgts[i] = port.WaiverFindingTarget{FindingID: uid.String()}
		}
		targets = &tgts
	}
	if err := u.requireWaiverScopeInProject(ctx, project.ID, derefSlice(contexts), derefSlice(targets)); err != nil {
		return nil, err
	}

	if err := u.validateWaiverUpdateScope(ctx, id.String(), input); err != nil {
		return nil, err
	}

	var expiry *port.WaiverExpiry
	if input.ClearExpiresAt {
		expiry = &port.WaiverExpiry{Clear: true}
	} else if input.ExpiresAt != nil {
		expiry = &port.WaiverExpiry{At: input.ExpiresAt}
	}

	actorID := stringPtr(input.ActorID)
	w, err := u.deps.Stores.Waivers.UpdateWithDetails(ctx, waiver, expiry, conditions, contexts, targets, port.WaiverEventInput{
		EventType: "updated",
		ActorID:   actorID,
		Metadata:  waiverCreatedEvent,
	})
	if err != nil {
		return nil, err
	}

	r := toWaiver(w)
	return &r, nil
}

// waiverContextInputs validates create/update waiver context inputs and
// keeps them as port context DTOs (an empty id is a wildcard for that field).
// A context that names none of the three would cover nothing, or by mistake
// everything, so it is refused.
func waiverContextInputs(inputs []CreateWaiverContextInput) ([]port.WaiverContext, error) {
	out := make([]port.WaiverContext, len(inputs))
	for i, c := range inputs {
		if c.EnvironmentID == "" && c.TargetID == "" && c.ArtifactID == "" {
			return nil, invalidWaiverRequest("a context needs an environment_id, target_id or artifact_id")
		}
		envID, err := parseOptionalUUID(c.EnvironmentID, "environment_id")
		if err != nil {
			return nil, err
		}
		targetID, err := parseOptionalUUID(c.TargetID, "target_id")
		if err != nil {
			return nil, err
		}
		artifactID, err := parseOptionalUUID(c.ArtifactID, "artifact_id")
		if err != nil {
			return nil, err
		}
		out[i] = port.WaiverContext{
			EnvironmentID: envID,
			TargetID:      targetID,
			ArtifactID:    artifactID,
		}
	}
	return out, nil
}

// parseOptionalUUID validates an optional UUID field, returning an error
// labeled with the field name when the value is present but malformed.
func parseOptionalUUID(value, field string) (string, error) {
	if value == "" {
		return "", nil
	}
	id, err := uuid.Parse(value)
	if err != nil {
		return "", invalidWaiverRequest("invalid %s %q", field, value)
	}
	return id.String(), nil
}

// derefSlice returns the slice a pointer holds, or nil for a nil pointer.
func derefSlice[T any](p *[]T) []T {
	if p == nil {
		return nil
	}
	return *p
}

// requireWaiverScopeInProject checks that every finding, environment, target
// and artifact a waiver names belongs to the project. It answers
// ErrWaiverScopeNotFound for an id that is missing and for one that belongs to
// another project alike, so the answer does not reveal which ids exist
// elsewhere. Each distinct id is looked up once.
func (u *Usecases) requireWaiverScopeInProject(ctx context.Context, projectID string, contexts []port.WaiverContext, targets []port.WaiverFindingTarget) error {
	checked := make(map[string]bool)
	once := func(kind, id string) bool {
		key := kind + ":" + id
		if id == "" || checked[key] {
			return false
		}
		checked[key] = true
		return true
	}
	notFound := func(kind string) error {
		return &waiverScopeError{message: kind + " not found in this project"}
	}
	for _, t := range targets {
		if !once("finding", t.FindingID) {
			continue
		}
		finding, err := u.deps.Stores.Findings.GetByID(ctx, t.FindingID)
		if errors.Is(err, port.ErrNotFound) || (err == nil && finding.ProjectID != projectID) {
			return notFound("finding")
		}
		if err != nil {
			return fmt.Errorf("get finding: %w", err)
		}
	}
	for _, c := range contexts {
		if once("environment", c.EnvironmentID) {
			if _, err := u.deps.Stores.Environments.GetByID(ctx, c.EnvironmentID, projectID); errors.Is(err, port.ErrNotFound) {
				return notFound("environment")
			} else if err != nil {
				return fmt.Errorf("get environment: %w", err)
			}
		}
		if once("target", c.TargetID) {
			if _, err := u.deps.Stores.Targets.GetByID(ctx, c.TargetID, projectID); errors.Is(err, port.ErrNotFound) {
				return notFound("target")
			} else if err != nil {
				return fmt.Errorf("get target: %w", err)
			}
		}
		if once("artifact", c.ArtifactID) {
			if _, err := u.deps.Stores.Artifacts.GetByID(ctx, c.ArtifactID, projectID); errors.Is(err, port.ErrNotFound) {
				return notFound("artifact")
			} else if err != nil {
				return fmt.Errorf("get artifact: %w", err)
			}
		}
	}
	return nil
}

func (u *Usecases) DeleteWaiver(ctx context.Context, projectSlug, waiverID string) error {
	project, err := u.deps.Stores.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return fmt.Errorf(errLookupProjectFormat, projectSlug, err)
	}
	if err := u.requireProjectAdminForWaiver(ctx, project.ID); err != nil {
		return err
	}

	id, err := uuid.Parse(waiverID)
	if err != nil {
		return fmt.Errorf(errInvalidWaiverIDFormat, err)
	}

	var actorID string
	if ident := auth.ContextIdentity(ctx); ident != nil {
		actorID = ident.UserID
	}
	if err := u.deps.Stores.Waivers.Delete(ctx, id.String(), project.ID, actorID); err != nil {
		return fmt.Errorf("delete waiver: %w", err)
	}
	return nil
}

func (u *Usecases) ToggleWaiver(ctx context.Context, projectSlug, waiverID, actorID string) (*WaiverResponse, error) {
	project, err := u.deps.Stores.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return nil, fmt.Errorf(errLookupProjectFormat, projectSlug, err)
	}
	if err := u.requireProjectAdminForWaiver(ctx, project.ID); err != nil {
		return nil, err
	}

	id, err := uuid.Parse(waiverID)
	if err != nil {
		return nil, fmt.Errorf(errInvalidWaiverIDFormat, err)
	}

	w, err := u.deps.Stores.Waivers.ToggleWithEvent(ctx, id.String(), project.ID, actorID)
	if err != nil {
		return nil, fmt.Errorf("toggle waiver: %w", err)
	}

	resp := toWaiver(w)
	return &resp, nil
}

// RevokeWaiver switches an approved waiver off. Revoking a waiver that is
// already off succeeds without a new event. A non-nil expectedUpdatedAt makes
// the call fail with ErrWaiverChanged when the waiver was written since.
func (u *Usecases) RevokeWaiver(ctx context.Context, projectSlug, waiverID, actorID string, expectedUpdatedAt *time.Time) (*WaiverResponse, error) {
	return u.setWaiverEnabled(ctx, projectSlug, waiverID, actorID, false, expectedUpdatedAt)
}

// RestoreWaiver switches a revoked waiver back on. It fails with
// ErrWaiverLapsed once the waiver's expiry has passed.
func (u *Usecases) RestoreWaiver(ctx context.Context, projectSlug, waiverID, actorID string, expectedUpdatedAt *time.Time) (*WaiverResponse, error) {
	return u.setWaiverEnabled(ctx, projectSlug, waiverID, actorID, true, expectedUpdatedAt)
}

func (u *Usecases) setWaiverEnabled(ctx context.Context, projectSlug, waiverID, actorID string, enabled bool, expectedUpdatedAt *time.Time) (*WaiverResponse, error) {
	project, err := u.deps.Stores.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return nil, fmt.Errorf(errLookupProjectFormat, projectSlug, err)
	}
	if err := u.requireProjectAdminForWaiver(ctx, project.ID); err != nil {
		return nil, err
	}

	id, err := uuid.Parse(waiverID)
	if err != nil {
		return nil, fmt.Errorf(errInvalidWaiverIDFormat, err)
	}

	eventType, verb := "revoked", "revoke"
	if enabled {
		eventType, verb = "restored", "restore"
	}
	w, err := u.deps.Stores.Waivers.SetEnabled(ctx, id.String(), project.ID, port.WaiverEnabledChange{
		Enabled:           enabled,
		ExpectedUpdatedAt: expectedUpdatedAt,
		Event: port.WaiverEventInput{
			EventType: eventType,
			ActorID:   &actorID,
			Metadata:  json.RawMessage(`{}`),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("%s waiver: %w", verb, err)
	}

	resp := toWaiver(w)
	return &resp, nil
}

func (u *Usecases) ListWaiverEvents(ctx context.Context, projectSlug, waiverID string) ([]WaiverEventResp, error) {
	project, err := u.deps.Stores.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return nil, fmt.Errorf(errLookupProjectFormat, projectSlug, err)
	}
	if err := u.requireProjectMember(ctx, project.ID); err != nil {
		return nil, err
	}

	id, err := uuid.Parse(waiverID)
	if err != nil {
		return nil, fmt.Errorf(errInvalidWaiverIDFormat, err)
	}

	if _, err := u.deps.Stores.Waivers.GetByID(ctx, id.String(), project.ID); err != nil {
		return nil, fmt.Errorf("get waiver: %w", err)
	}

	events, err := u.deps.Stores.Waivers.ListEvents(ctx, id.String())
	if err != nil {
		return nil, fmt.Errorf("list events: %w", err)
	}

	resp := make([]WaiverEventResp, len(events))
	actors := make([]string, 0, len(events))
	for i, e := range events {
		resp[i] = toWaiverEvent(e)
		actors = append(actors, e.ActorID)
	}
	labels := u.peopleLabels(ctx, actors)
	for i := range resp {
		resp[i].ActorName = labels[resp[i].ActorID]
	}
	return resp, nil
}

func (u *Usecases) CheckWaiverMatch(ctx context.Context, projectSlug, findingID string) (bool, error) {
	project, err := u.deps.Stores.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return false, fmt.Errorf(errLookupProjectFormat, projectSlug, err)
	}

	fid, err := uuid.Parse(findingID)
	if err != nil {
		return false, fmt.Errorf("invalid finding id: %w", err)
	}

	finding, err := u.deps.Stores.Findings.GetByID(ctx, fid.String())
	if err != nil {
		return false, fmt.Errorf("get finding: %w", err)
	}
	if finding.ProjectID != project.ID {
		return false, ErrProjectAccessDenied
	}
	if err := u.checkFindingProjectIDAccess(ctx, finding.ProjectID); err != nil {
		return false, err
	}

	gf := gate.Finding{
		ID:                  finding.ID,
		CurrentSeverityRank: finding.CurrentSeverityRank,
		FindingKind:         finding.FindingKind,
		Fingerprint:         finding.Fingerprint,
		CurrentTitle:        finding.CurrentTitle,
	}
	if fc, ctxErr := u.deps.Stores.Findings.GetFindingContext(ctx, fid.String()); ctxErr == nil {
		gf.EnvironmentID = fc.EnvironmentID
		gf.EnvironmentIDs = fc.EnvironmentIDs
		gf.TargetID = fc.TargetID
		gf.ArtifactID = fc.ArtifactID
	}

	dimensions, err := u.deps.Stores.Findings.ListDimensions(ctx, fid.String())
	if err != nil {
		return false, fmt.Errorf("load finding aliases: %w", err)
	}
	for _, d := range dimensions {
		if d.Key == "alias" {
			gf.Aliases = append(gf.Aliases, d.Value)
		}
	}

	waivers, err := (&gateWaiverRepo{stores: u.deps.Stores}).ListActiveWaivers(ctx, project.ID)
	if err != nil {
		return false, fmt.Errorf("list active waivers: %w", err)
	}

	return gate.IsFindingWaived(gf, waivers), nil
}

func stringPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
