package usecase

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/xMinhx/specht/internal/db/sqlc"
	"github.com/xMinhx/specht/internal/gate"
	"github.com/xMinhx/specht/internal/repo"
)

// WaiverResponse is the API representation of a waiver with its condition,
// context, and target rows attached.
type WaiverResponse struct {
	ID          string                    `json:"id"`
	ProjectID   string                    `json:"project_id"`
	Name        string                    `json:"name"`
	Description string                    `json:"description"`
	Enabled     bool                      `json:"enabled"`
	Conditions  []WaiverConditionResp     `json:"conditions"`
	Contexts    []WaiverContextResp       `json:"contexts"`
	Targets     []WaiverFindingTargetResp `json:"targets"`
	CreatedAt   string                    `json:"created_at"`
	UpdatedAt   string                    `json:"updated_at"`
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
	Metadata  json.RawMessage `json:"metadata,omitempty"`
	CreatedAt string          `json:"created_at"`
}

// CreateWaiverInput is a request to create a waiver: a name/description plus
// optional conditions, deployment-context scopes, and directly-targeted
// finding ids. An empty Conditions/Contexts/Targets set makes the waiver
// apply to every blocking finding in the project.
type CreateWaiverInput struct {
	ProjectSlug string
	Name        string
	Description string
	Conditions  []CreateWaiverConditionInput
	Contexts    []CreateWaiverContextInput
	TargetIDs   []string
	ActorID     string
}

// CreateWaiverConditionInput is a condition input for waiver create/update.
type CreateWaiverConditionInput struct {
	Field    string
	Operator string
	Value    string
}

// CreateWaiverContextInput is a context scope input for waiver create/update.
type CreateWaiverContextInput struct {
	EnvironmentID string
	TargetID      string
	ArtifactID    string
}

// UpdateWaiverInput is a request to update a waiver. Name and Description
// replace the stored values when non-empty; a non-nil Conditions/Contexts/
// TargetIDs slice replaces that child set (nil leaves it untouched).
type UpdateWaiverInput struct {
	WaiverID    string
	ProjectSlug string
	Name        string
	Description string
	Conditions  []CreateWaiverConditionInput
	Contexts    []CreateWaiverContextInput
	TargetIDs   []string
	ActorID     string
}

// WaiverDetailResponse is a waiver with full condition/context/target rows.
type WaiverDetailResponse struct {
	WaiverResponse
	Conditions []WaiverConditionResp     `json:"conditions"`
	Contexts   []WaiverContextResp       `json:"contexts"`
	Targets    []WaiverFindingTargetResp `json:"targets"`
}

func toWaiver(w sqlc.Waiver) WaiverResponse {
	return WaiverResponse{
		ID:          uuidStr(w.ID),
		ProjectID:   uuidStr(w.ProjectID),
		Name:        w.Name,
		Description: w.Description,
		Enabled:     w.Enabled,
		Conditions:  make([]WaiverConditionResp, 0),
		Contexts:    make([]WaiverContextResp, 0),
		Targets:     make([]WaiverFindingTargetResp, 0),
		CreatedAt:   w.CreatedAt.Time.Format(time.RFC3339),
		UpdatedAt:   w.UpdatedAt.Time.Format(time.RFC3339),
	}
}

func toWaiverCondition(c sqlc.WaiverCondition) WaiverConditionResp {
	return WaiverConditionResp{
		ID:       uuidStr(c.ID),
		Field:    c.Field,
		Operator: c.Operator,
		Value:    c.Value,
	}
}

func toWaiverContext(c sqlc.WaiverContext) WaiverContextResp {
	return WaiverContextResp{
		ID:            uuidStr(c.ID),
		EnvironmentID: uuidStr(c.EnvironmentID),
		TargetID:      uuidStr(c.TargetID),
		ArtifactID:    uuidStr(c.ArtifactID),
	}
}

func toWaiverFindingTarget(t sqlc.WaiverFindingTarget) WaiverFindingTargetResp {
	return WaiverFindingTargetResp{
		ID:        uuidStr(t.ID),
		FindingID: uuidStr(t.FindingID),
	}
}

func toWaiverEvent(e sqlc.WaiverEvent) WaiverEventResp {
	actorID := ""
	if e.ActorID.Valid {
		actorID = e.ActorID.String
	}
	return WaiverEventResp{
		ID:        uuidStr(e.ID),
		WaiverID:  uuidStr(e.WaiverID),
		EventType: e.EventType,
		ActorID:   actorID,
		Metadata:  e.Metadata,
		CreatedAt: e.CreatedAt.Time.Format(time.RFC3339),
	}
}

func toWaiverDetail(w sqlc.Waiver, conditions []sqlc.WaiverCondition, contexts []sqlc.WaiverContext, targets []sqlc.WaiverFindingTarget) WaiverDetailResponse {
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
	project, err := u.deps.Repos.Projects.GetBySlug(ctx, input.ProjectSlug)
	if err != nil {
		return nil, fmt.Errorf("lookup project %q: %w", input.ProjectSlug, err)
	}

	conditions := make([]repo.WaiverConditionInput, len(input.Conditions))
	for i, c := range input.Conditions {
		conditions[i] = repo.WaiverConditionInput{
			Field:    c.Field,
			Operator: c.Operator,
			Value:    c.Value,
		}
	}

	contexts, err := waiverContextInputs(input.Contexts)
	if err != nil {
		return nil, err
	}

	targets := make([]repo.WaiverTargetInput, len(input.TargetIDs))
	for i, targetID := range input.TargetIDs {
		id, err := uuid.Parse(targetID)
		if err != nil {
			return nil, fmt.Errorf("invalid target finding id %q: %w", targetID, err)
		}
		targets[i] = repo.WaiverTargetInput{FindingID: pgtype.UUID{Bytes: id, Valid: true}}
	}

	w, err := u.deps.Repos.Waivers.CreateWithDetails(ctx, repo.CreateWaiverDetailsParams{
		ProjectID:   project.ID,
		Name:        input.Name,
		Description: input.Description,
		Enabled:     true,
		Conditions:  conditions,
		Contexts:    contexts,
		Targets:     targets,
		Event: repo.WaiverEventInput{
			EventType: "created",
			ActorID:   textPtr(input.ActorID),
			Metadata:  waiverCreatedEvent,
		},
	})
	if err != nil {
		return nil, err
	}

	r := toWaiver(w)
	return &r, nil
}

func (u *Usecases) ListWaivers(ctx context.Context, projectSlug string) ([]WaiverResponse, error) {
	project, err := u.deps.Repos.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return nil, fmt.Errorf("lookup project %q: %w", projectSlug, err)
	}

	waivers, err := u.deps.Repos.Waivers.List(ctx, project.ID)
	if err != nil {
		return nil, fmt.Errorf("list waivers: %w", err)
	}

	resp := make([]WaiverResponse, len(waivers))
	for i, w := range waivers {
		resp[i] = toWaiver(w)
	}
	return resp, nil
}

func (u *Usecases) GetWaiver(ctx context.Context, projectSlug, waiverID string) (*WaiverDetailResponse, error) {
	project, err := u.deps.Repos.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return nil, fmt.Errorf("lookup project %q: %w", projectSlug, err)
	}

	id, err := uuid.Parse(waiverID)
	if err != nil {
		return nil, fmt.Errorf("invalid waiver id: %w", err)
	}

	w, err := u.deps.Repos.Waivers.GetByID(ctx, pgtype.UUID{Bytes: id, Valid: true}, project.ID)
	if err != nil {
		return nil, fmt.Errorf("get waiver: %w", err)
	}

	conditions, err := u.deps.Repos.Waivers.ListConditions(ctx, w.ID)
	if err != nil {
		return nil, fmt.Errorf("list conditions: %w", err)
	}

	contexts, err := u.deps.Repos.Waivers.ListContexts(ctx, w.ID)
	if err != nil {
		return nil, fmt.Errorf("list contexts: %w", err)
	}

	targets, err := u.deps.Repos.Waivers.ListFindingTargets(ctx, w.ID)
	if err != nil {
		return nil, fmt.Errorf("list finding targets: %w", err)
	}

	resp := toWaiverDetail(w, conditions, contexts, targets)
	return &resp, nil
}

func (u *Usecases) UpdateWaiver(ctx context.Context, input UpdateWaiverInput) (*WaiverResponse, error) {
	project, err := u.deps.Repos.Projects.GetBySlug(ctx, input.ProjectSlug)
	if err != nil {
		return nil, fmt.Errorf("lookup project %q: %w", input.ProjectSlug, err)
	}

	id, err := uuid.Parse(input.WaiverID)
	if err != nil {
		return nil, fmt.Errorf("invalid waiver id: %w", err)
	}
	pid := pgtype.UUID{Bytes: id, Valid: true}

	var conditions []repo.WaiverConditionInput
	if input.Conditions != nil {
		conditions = make([]repo.WaiverConditionInput, len(input.Conditions))
		for i, c := range input.Conditions {
			conditions[i] = repo.WaiverConditionInput{
				Field:    c.Field,
				Operator: c.Operator,
				Value:    c.Value,
			}
		}
	}

	var contexts []repo.WaiverContextInput
	if input.Contexts != nil {
		contexts, err = waiverContextInputs(input.Contexts)
		if err != nil {
			return nil, err
		}
	}

	var targets []repo.WaiverTargetInput
	if input.TargetIDs != nil {
		targets = make([]repo.WaiverTargetInput, len(input.TargetIDs))
		for i, targetID := range input.TargetIDs {
			uid, err := uuid.Parse(targetID)
			if err != nil {
				return nil, fmt.Errorf("invalid target finding id %q: %w", targetID, err)
			}
			targets[i] = repo.WaiverTargetInput{FindingID: pgtype.UUID{Bytes: uid, Valid: true}}
		}
	}

	w, err := u.deps.Repos.Waivers.UpdateWithDetails(ctx, repo.UpdateWaiverDetailsParams{
		ID:          pid,
		ProjectID:   project.ID,
		Name:        input.Name,
		Description: input.Description,
		Conditions:  conditions,
		Contexts:    contexts,
		Targets:     targets,
		Event: repo.WaiverEventInput{
			EventType: "updated",
			ActorID:   textPtr(input.ActorID),
			Metadata:  waiverCreatedEvent,
		},
	})
	if err != nil {
		return nil, err
	}

	r := toWaiver(w)
	return &r, nil
}

// waiverContextInputs validates and converts create/update waiver context
// inputs into repo context inputs with parsed UUIDs.
func waiverContextInputs(inputs []CreateWaiverContextInput) ([]repo.WaiverContextInput, error) {
	out := make([]repo.WaiverContextInput, len(inputs))
	for i, c := range inputs {
		if c.EnvironmentID != "" {
			id, err := uuid.Parse(c.EnvironmentID)
			if err != nil {
				return nil, fmt.Errorf("invalid environment_id %q: %w", c.EnvironmentID, err)
			}
			out[i].EnvironmentID = pgtype.UUID{Bytes: id, Valid: true}
		}
		if c.TargetID != "" {
			id, err := uuid.Parse(c.TargetID)
			if err != nil {
				return nil, fmt.Errorf("invalid target_id %q: %w", c.TargetID, err)
			}
			out[i].TargetID = pgtype.UUID{Bytes: id, Valid: true}
		}
		if c.ArtifactID != "" {
			id, err := uuid.Parse(c.ArtifactID)
			if err != nil {
				return nil, fmt.Errorf("invalid artifact_id %q: %w", c.ArtifactID, err)
			}
			out[i].ArtifactID = pgtype.UUID{Bytes: id, Valid: true}
		}
	}
	return out, nil
}

func (u *Usecases) DeleteWaiver(ctx context.Context, projectSlug, waiverID string) error {
	project, err := u.deps.Repos.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return fmt.Errorf("lookup project %q: %w", projectSlug, err)
	}

	id, err := uuid.Parse(waiverID)
	if err != nil {
		return fmt.Errorf("invalid waiver id: %w", err)
	}

	_, err = u.deps.Repos.Waivers.Delete(ctx, pgtype.UUID{Bytes: id, Valid: true}, project.ID)
	if err != nil {
		return fmt.Errorf("delete waiver: %w", err)
	}
	return nil
}

func (u *Usecases) ToggleWaiver(ctx context.Context, projectSlug, waiverID, actorID string) (*WaiverResponse, error) {
	project, err := u.deps.Repos.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return nil, fmt.Errorf("lookup project %q: %w", projectSlug, err)
	}

	id, err := uuid.Parse(waiverID)
	if err != nil {
		return nil, fmt.Errorf("invalid waiver id: %w", err)
	}

	w, err := u.deps.Repos.Waivers.Toggle(ctx, pgtype.UUID{Bytes: id, Valid: true}, project.ID)
	if err != nil {
		return nil, fmt.Errorf("toggle waiver: %w", err)
	}

	eventType := "enabled"
	if !w.Enabled {
		eventType = "disabled"
	}
	u.deps.Repos.Waivers.CreateEvent(ctx, sqlc.CreateWaiverEventParams{
		WaiverID:  w.ID,
		EventType: eventType,
		ActorID:   textPtr(actorID),
		Metadata:  waiverCreatedEvent,
	})

	resp := toWaiver(w)
	return &resp, nil
}

func (u *Usecases) ListWaiverEvents(ctx context.Context, projectSlug, waiverID string) ([]WaiverEventResp, error) {
	project, err := u.deps.Repos.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return nil, fmt.Errorf("lookup project %q: %w", projectSlug, err)
	}

	id, err := uuid.Parse(waiverID)
	if err != nil {
		return nil, fmt.Errorf("invalid waiver id: %w", err)
	}

	_, err = u.deps.Repos.Waivers.GetByID(ctx, pgtype.UUID{Bytes: id, Valid: true}, project.ID)
	if err != nil {
		return nil, fmt.Errorf("get waiver: %w", err)
	}

	events, err := u.deps.Repos.Waivers.ListEvents(ctx, pgtype.UUID{Bytes: id, Valid: true})
	if err != nil {
		return nil, fmt.Errorf("list events: %w", err)
	}

	resp := make([]WaiverEventResp, len(events))
	for i, e := range events {
		resp[i] = toWaiverEvent(e)
	}
	return resp, nil
}

func (u *Usecases) CheckWaiverMatch(ctx context.Context, projectSlug, findingID string) (bool, error) {
	project, err := u.deps.Repos.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return false, fmt.Errorf("lookup project %q: %w", projectSlug, err)
	}

	fid, err := uuid.Parse(findingID)
	if err != nil {
		return false, fmt.Errorf("invalid finding id: %w", err)
	}
	findingUUID := pgtype.UUID{Bytes: fid, Valid: true}

	finding, err := u.deps.Repos.Findings.GetByID(ctx, findingUUID)
	if err != nil {
		return false, fmt.Errorf("get finding: %w", err)
	}

	gf := gate.Finding{
		ID:                  uuid.UUID(finding.ID.Bytes).String(),
		CurrentSeverityRank: finding.CurrentSeverityRank,
		FindingKind:         finding.FindingKind,
		Fingerprint:         finding.Fingerprint,
		CurrentTitle:        finding.CurrentTitle,
	}
	if fc, ctxErr := u.deps.Repos.Findings.GetFindingContext(ctx, findingUUID); ctxErr == nil {
		if fc.EnvironmentID.Valid {
			gf.EnvironmentID = uuid.UUID(fc.EnvironmentID.Bytes).String()
		}
		if fc.TargetID.Valid {
			gf.TargetID = uuid.UUID(fc.TargetID.Bytes).String()
		}
		if fc.ArtifactID.Valid {
			gf.ArtifactID = uuid.UUID(fc.ArtifactID.Bytes).String()
		}
	}

	projectID := uuid.UUID(project.ID.Bytes).String()
	waivers, err := (&gateWaiverRepo{r: u.deps.Repos.Waivers}).ListActiveWaivers(ctx, projectID)
	if err != nil {
		return false, fmt.Errorf("list active waivers: %w", err)
	}

	return gate.IsFindingWaived(gf, waivers), nil
}
