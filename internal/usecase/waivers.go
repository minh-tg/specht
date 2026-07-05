package usecase

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/xMinhx/specht/internal/db/sqlc"
)

type WaiverResponse struct {
	ID          string                   `json:"id"`
	ProjectID   string                   `json:"project_id"`
	Name        string                   `json:"name"`
	Description string                   `json:"description"`
	Enabled     bool                     `json:"enabled"`
	Conditions  []WaiverConditionResp   `json:"conditions"`
	Contexts    []WaiverContextResp      `json:"contexts"`
	Targets     []WaiverFindingTargetResp `json:"targets"`
	CreatedAt   string                   `json:"created_at"`
	UpdatedAt   string                   `json:"updated_at"`
}

type WaiverConditionResp struct {
	ID       string `json:"id"`
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
}

type WaiverContextResp struct {
	ID            string `json:"id"`
	EnvironmentID string `json:"environment_id,omitempty"`
	TargetID      string `json:"target_id,omitempty"`
	ArtifactID    string `json:"artifact_id,omitempty"`
}

type WaiverFindingTargetResp struct {
	ID        string `json:"id"`
	FindingID string `json:"finding_id"`
}

type WaiverEventResp struct {
	ID        string          `json:"id"`
	WaiverID  string          `json:"waiver_id"`
	EventType string          `json:"event_type"`
	ActorID   string          `json:"actor_id,omitempty"`
	Metadata  json.RawMessage `json:"metadata,omitempty"`
	CreatedAt string          `json:"created_at"`
}

type CreateWaiverInput struct {
	ProjectSlug string
	Name        string
	Description string
	Conditions  []CreateWaiverConditionInput
	Contexts    []CreateWaiverContextInput
	TargetIDs   []string
}

type CreateWaiverConditionInput struct {
	Field    string
	Operator string
	Value    string
}

type CreateWaiverContextInput struct {
	EnvironmentID string
	TargetID      string
	ArtifactID    string
}

type UpdateWaiverInput struct {
	WaiverID    string
	ProjectSlug string
	Name        string
	Description string
	Conditions  []CreateWaiverConditionInput
	Contexts    []CreateWaiverContextInput
	TargetIDs   []string
}

type WaiverDetailResponse struct {
	WaiverResponse
	Conditions []WaiverConditionResp      `json:"conditions"`
	Contexts   []WaiverContextResp        `json:"contexts"`
	Targets    []WaiverFindingTargetResp  `json:"targets"`
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
	return WaiverEventResp{
		ID:        uuidStr(e.ID),
		WaiverID:  uuidStr(e.WaiverID),
		EventType: e.EventType,
		ActorID:   uuidStr(e.ActorID),
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
		return nil, err
	}

	w, err := u.deps.Repos.Waivers.Create(ctx, sqlc.CreateWaiverParams{
		ProjectID:   project.ID,
		Name:        input.Name,
		Description: input.Description,
		Enabled:     true,
	})
	if err != nil {
		return nil, err
	}

	for _, c := range input.Conditions {
		_, err = u.deps.Repos.Waivers.CreateCondition(ctx, sqlc.CreateWaiverConditionParams{
			WaiverID: w.ID,
			Field:    c.Field,
			Operator: c.Operator,
			Value:    c.Value,
		})
		if err != nil {
			return nil, err
		}
	}

	for _, c := range input.Contexts {
		envID := pgtype.UUID{Valid: false}
		if c.EnvironmentID != "" {
			id, _ := uuid.Parse(c.EnvironmentID)
			envID = pgtype.UUID{Bytes: id, Valid: true}
		}
		tgtID := pgtype.UUID{Valid: false}
		if c.TargetID != "" {
			id, _ := uuid.Parse(c.TargetID)
			tgtID = pgtype.UUID{Bytes: id, Valid: true}
		}
		artID := pgtype.UUID{Valid: false}
		if c.ArtifactID != "" {
			id, _ := uuid.Parse(c.ArtifactID)
			artID = pgtype.UUID{Bytes: id, Valid: true}
		}
		_, err = u.deps.Repos.Waivers.CreateContext(ctx, sqlc.CreateWaiverContextParams{
			WaiverID:      w.ID,
			EnvironmentID: envID,
			TargetID:      tgtID,
			ArtifactID:    artID,
		})
		if err != nil {
			return nil, err
		}
	}

	for _, targetID := range input.TargetIDs {
		id, _ := uuid.Parse(targetID)
		_, err = u.deps.Repos.Waivers.CreateFindingTarget(ctx, sqlc.CreateWaiverFindingTargetParams{
			WaiverID:  w.ID,
			FindingID: pgtype.UUID{Bytes: id, Valid: true},
		})
		if err != nil {
			return nil, err
		}
	}

	u.deps.Repos.Waivers.CreateEvent(ctx, sqlc.CreateWaiverEventParams{
		WaiverID:  w.ID,
		EventType: "created",
		ActorID:   pgtype.UUID{Valid: false},
		Metadata:  waiverCreatedEvent,
	})

	resp := toWaiver(w)
	return &resp, nil
}

func (u *Usecases) ListWaivers(ctx context.Context, projectSlug string) ([]WaiverResponse, error) {
	project, err := u.deps.Repos.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return nil, err
	}

	waivers, err := u.deps.Repos.Waivers.List(ctx, project.ID)
	if err != nil {
		return nil, err
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
		return nil, err
	}

	w, err := u.deps.Repos.Waivers.GetByID(ctx, pgtype.UUID{}, project.ID)
	if err != nil {
		return nil, err
	}

	conditions, err := u.deps.Repos.Waivers.ListConditions(ctx, w.ID)
	if err != nil {
		return nil, err
	}

	contexts, err := u.deps.Repos.Waivers.ListContexts(ctx, w.ID)
	if err != nil {
		return nil, err
	}

	targets, err := u.deps.Repos.Waivers.ListFindingTargets(ctx, w.ID)
	if err != nil {
		return nil, err
	}

	resp := toWaiverDetail(w, conditions, contexts, targets)
	return &resp, nil
}

func (u *Usecases) UpdateWaiver(ctx context.Context, input UpdateWaiverInput) (*WaiverResponse, error) {
	project, err := u.deps.Repos.Projects.GetBySlug(ctx, input.ProjectSlug)
	if err != nil {
		return nil, err
	}

	w, err := u.deps.Repos.Waivers.Update(ctx, sqlc.UpdateWaiverParams{
		ID:          pgtype.UUID{},
		ProjectID:   project.ID,
		Name:        pgtype.Text{String: input.Name, Valid: input.Name != ""},
		Description: pgtype.Text{String: input.Description, Valid: input.Description != ""},
	})
	if err != nil {
		return nil, err
	}

	if input.Conditions != nil {
		u.deps.Repos.Waivers.DeleteConditions(ctx, w.ID)
		for _, c := range input.Conditions {
			u.deps.Repos.Waivers.CreateCondition(ctx, sqlc.CreateWaiverConditionParams{
				WaiverID: w.ID,
				Field:    c.Field,
				Operator: c.Operator,
				Value:    c.Value,
			})
		}
	}

	if input.Contexts != nil {
		u.deps.Repos.Waivers.DeleteContexts(ctx, w.ID)
		for _, c := range input.Contexts {
			envID := pgtype.UUID{Valid: false}
			if c.EnvironmentID != "" {
				id, _ := uuid.Parse(c.EnvironmentID)
				envID = pgtype.UUID{Bytes: id, Valid: true}
			}
			tgtID := pgtype.UUID{Valid: false}
			if c.TargetID != "" {
				id, _ := uuid.Parse(c.TargetID)
				tgtID = pgtype.UUID{Bytes: id, Valid: true}
			}
			artID := pgtype.UUID{Valid: false}
			if c.ArtifactID != "" {
				id, _ := uuid.Parse(c.ArtifactID)
				artID = pgtype.UUID{Bytes: id, Valid: true}
			}
			u.deps.Repos.Waivers.CreateContext(ctx, sqlc.CreateWaiverContextParams{
				WaiverID:      w.ID,
				EnvironmentID: envID,
				TargetID:      tgtID,
				ArtifactID:    artID,
			})
		}
	}

	if input.TargetIDs != nil {
		u.deps.Repos.Waivers.DeleteFindingTargets(ctx, w.ID)
		for _, targetID := range input.TargetIDs {
			id, _ := uuid.Parse(targetID)
			u.deps.Repos.Waivers.CreateFindingTarget(ctx, sqlc.CreateWaiverFindingTargetParams{
				WaiverID:  w.ID,
				FindingID: pgtype.UUID{Bytes: id, Valid: true},
			})
		}
	}

	u.deps.Repos.Waivers.CreateEvent(ctx, sqlc.CreateWaiverEventParams{
		WaiverID:  w.ID,
		EventType: "updated",
		ActorID:   pgtype.UUID{Valid: false},
		Metadata:  waiverCreatedEvent,
	})

	resp := toWaiver(w)
	return &resp, nil
}

func (u *Usecases) DeleteWaiver(ctx context.Context, projectSlug, waiverID string) error {
	project, err := u.deps.Repos.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return err
	}

	_, err = u.deps.Repos.Waivers.Delete(ctx, pgtype.UUID{}, project.ID)
	if err != nil {
		return err
	}
	return nil
}

func (u *Usecases) ToggleWaiver(ctx context.Context, projectSlug, waiverID string) (*WaiverResponse, error) {
	project, err := u.deps.Repos.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return nil, err
	}

	w, err := u.deps.Repos.Waivers.Toggle(ctx, pgtype.UUID{}, project.ID)
	if err != nil {
		return nil, err
	}

	eventType := "enabled"
	if !w.Enabled {
		eventType = "disabled"
	}
	u.deps.Repos.Waivers.CreateEvent(ctx, sqlc.CreateWaiverEventParams{
		WaiverID:  w.ID,
		EventType: eventType,
		ActorID:   pgtype.UUID{Valid: false},
		Metadata:  waiverCreatedEvent,
	})

	resp := toWaiver(w)
	return &resp, nil
}

func (u *Usecases) ListWaiverEvents(ctx context.Context, projectSlug, waiverID string) ([]WaiverEventResp, error) {
	project, err := u.deps.Repos.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return nil, err
	}

	w, err := u.deps.Repos.Waivers.GetByID(ctx, pgtype.UUID{}, project.ID)
	if err != nil {
		return nil, err
	}

	events, err := u.deps.Repos.Waivers.ListEvents(ctx, w.ID)
	if err != nil {
		return nil, err
	}

	resp := make([]WaiverEventResp, len(events))
	for i, e := range events {
		resp[i] = toWaiverEvent(e)
	}
	return resp, nil
}

func (u *Usecases) CheckWaiverMatch(ctx context.Context, projectSlug, findingID string) (bool, error) {
	return false, nil
}
