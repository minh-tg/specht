package usecase

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/xMinhx/specht/internal/db/sqlc"
)

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
	ActorID     string
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
	ActorID     string
}

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

	var resp *WaiverResponse
	err = u.deps.Repos.WithTx(ctx, func(q *sqlc.Queries) error {
		w, err := q.CreateWaiver(ctx, sqlc.CreateWaiverParams{
			ProjectID:   project.ID,
			Name:        input.Name,
			Description: input.Description,
			Enabled:     true,
		})
		if err != nil {
			return fmt.Errorf("create waiver: %w", err)
		}

		for _, c := range input.Conditions {
			_, err = q.CreateWaiverCondition(ctx, sqlc.CreateWaiverConditionParams{
				WaiverID: w.ID,
				Field:    c.Field,
				Operator: c.Operator,
				Value:    c.Value,
			})
			if err != nil {
				return fmt.Errorf("create condition: %w", err)
			}
		}

		for _, c := range input.Contexts {
			envID := pgtype.UUID{Valid: false}
			if c.EnvironmentID != "" {
				id, err := uuid.Parse(c.EnvironmentID)
				if err != nil {
					return fmt.Errorf("invalid environment_id %q: %w", c.EnvironmentID, err)
				}
				envID = pgtype.UUID{Bytes: id, Valid: true}
			}
			tgtID := pgtype.UUID{Valid: false}
			if c.TargetID != "" {
				id, err := uuid.Parse(c.TargetID)
				if err != nil {
					return fmt.Errorf("invalid target_id %q: %w", c.TargetID, err)
				}
				tgtID = pgtype.UUID{Bytes: id, Valid: true}
			}
			artID := pgtype.UUID{Valid: false}
			if c.ArtifactID != "" {
				id, err := uuid.Parse(c.ArtifactID)
				if err != nil {
					return fmt.Errorf("invalid artifact_id %q: %w", c.ArtifactID, err)
				}
				artID = pgtype.UUID{Bytes: id, Valid: true}
			}
			_, err = q.CreateWaiverContext(ctx, sqlc.CreateWaiverContextParams{
				WaiverID:      w.ID,
				EnvironmentID: envID,
				TargetID:      tgtID,
				ArtifactID:    artID,
			})
			if err != nil {
				return fmt.Errorf("create context: %w", err)
			}
		}

		for _, targetID := range input.TargetIDs {
			id, err := uuid.Parse(targetID)
			if err != nil {
				return fmt.Errorf("invalid target finding id %q: %w", targetID, err)
			}
			_, err = q.CreateWaiverFindingTarget(ctx, sqlc.CreateWaiverFindingTargetParams{
				WaiverID:  w.ID,
				FindingID: pgtype.UUID{Bytes: id, Valid: true},
			})
			if err != nil {
				return fmt.Errorf("create finding target: %w", err)
			}
		}

		q.CreateWaiverEvent(ctx, sqlc.CreateWaiverEventParams{
			WaiverID:  w.ID,
			EventType: "created",
			ActorID:   textPtr(input.ActorID),
			Metadata:  waiverCreatedEvent,
		})

		r := toWaiver(w)
		resp = &r
		return nil
	})

	return resp, err
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

	var resp *WaiverResponse
	err = u.deps.Repos.WithTx(ctx, func(q *sqlc.Queries) error {
		w, err := q.UpdateWaiver(ctx, sqlc.UpdateWaiverParams{
			ID:          pid,
			ProjectID:   project.ID,
			Name:        input.Name,
			Description: input.Description,
		})
		if err != nil {
			return fmt.Errorf("update waiver: %w", err)
		}

		if input.Conditions != nil {
			if err := q.DeleteWaiverConditions(ctx, w.ID); err != nil {
				return fmt.Errorf("delete conditions: %w", err)
			}
			for _, c := range input.Conditions {
				_, err = q.CreateWaiverCondition(ctx, sqlc.CreateWaiverConditionParams{
					WaiverID: w.ID,
					Field:    c.Field,
					Operator: c.Operator,
					Value:    c.Value,
				})
				if err != nil {
					return fmt.Errorf("create condition: %w", err)
				}
			}
		}

		if input.Contexts != nil {
			if err := q.DeleteWaiverContexts(ctx, w.ID); err != nil {
				return fmt.Errorf("delete contexts: %w", err)
			}
			for _, c := range input.Contexts {
				envID := pgtype.UUID{Valid: false}
				if c.EnvironmentID != "" {
					uid, err := uuid.Parse(c.EnvironmentID)
					if err != nil {
						return fmt.Errorf("invalid environment_id %q: %w", c.EnvironmentID, err)
					}
					envID = pgtype.UUID{Bytes: uid, Valid: true}
				}
				tgtID := pgtype.UUID{Valid: false}
				if c.TargetID != "" {
					uid, err := uuid.Parse(c.TargetID)
					if err != nil {
						return fmt.Errorf("invalid target_id %q: %w", c.TargetID, err)
					}
					tgtID = pgtype.UUID{Bytes: uid, Valid: true}
				}
				artID := pgtype.UUID{Valid: false}
				if c.ArtifactID != "" {
					uid, err := uuid.Parse(c.ArtifactID)
					if err != nil {
						return fmt.Errorf("invalid artifact_id %q: %w", c.ArtifactID, err)
					}
					artID = pgtype.UUID{Bytes: uid, Valid: true}
				}
				_, err = q.CreateWaiverContext(ctx, sqlc.CreateWaiverContextParams{
					WaiverID:      w.ID,
					EnvironmentID: envID,
					TargetID:      tgtID,
					ArtifactID:    artID,
				})
				if err != nil {
					return fmt.Errorf("create context: %w", err)
				}
			}
		}

		if input.TargetIDs != nil {
			if err := q.DeleteWaiverFindingTargets(ctx, w.ID); err != nil {
				return fmt.Errorf("delete targets: %w", err)
			}
			for _, targetID := range input.TargetIDs {
				uid, err := uuid.Parse(targetID)
				if err != nil {
					return fmt.Errorf("invalid target finding id %q: %w", targetID, err)
				}
				_, err = q.CreateWaiverFindingTarget(ctx, sqlc.CreateWaiverFindingTargetParams{
					WaiverID:  w.ID,
					FindingID: pgtype.UUID{Bytes: uid, Valid: true},
				})
				if err != nil {
					return fmt.Errorf("create finding target: %w", err)
				}
			}
		}

		q.CreateWaiverEvent(ctx, sqlc.CreateWaiverEventParams{
			WaiverID:  w.ID,
			EventType: "updated",
			ActorID:   textPtr(input.ActorID),
			Metadata:  waiverCreatedEvent,
		})

		r := toWaiver(w)
		resp = &r
		return nil
	})

	return resp, err
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

	waivers, err := u.deps.Repos.Waivers.ListActive(ctx, project.ID)
	if err != nil {
		return false, fmt.Errorf("list active waivers: %w", err)
	}

	finding, err := u.deps.Repos.Findings.GetByID(ctx, pgtype.UUID{Bytes: fid, Valid: true})
	if err != nil {
		return false, fmt.Errorf("get finding: %w", err)
	}

	for _, w := range waivers {
		conditions, err := u.deps.Repos.Waivers.ListConditions(ctx, w.ID)
		if err != nil {
			return false, fmt.Errorf("list conditions for waiver %s: %w", uuidStr(w.ID), err)
		}

		contexts, err := u.deps.Repos.Waivers.ListContexts(ctx, w.ID)
		if err != nil {
			return false, fmt.Errorf("list contexts for waiver %s: %w", uuidStr(w.ID), err)
		}

		targets, err := u.deps.Repos.Waivers.ListFindingTargets(ctx, w.ID)
		if err != nil {
			return false, fmt.Errorf("list targets for waiver %s: %w", uuidStr(w.ID), err)
		}

		if len(contexts) > 0 && !matchContexts(finding, contexts) {
			continue
		}

		if len(targets) > 0 && !matchTargets(finding, targets) {
			continue
		}

		matched := true
		for _, c := range conditions {
			if !matchCondition(finding, c) {
				matched = false
				break
			}
		}

		if matched {
			return true, nil
		}
	}

	return false, nil
}

func matchCondition(finding sqlc.Finding, cond sqlc.WaiverCondition) bool {
	switch cond.Field {
	case "severity_rank":
		threshold, err := strconv.Atoi(cond.Value)
		if err != nil {
			return false
		}
		switch cond.Operator {
		case "eq":
			return int(finding.CurrentSeverityRank) == threshold
		case "neq":
			return int(finding.CurrentSeverityRank) != threshold
		case "lt":
			return int(finding.CurrentSeverityRank) < threshold
		case "lte":
			return int(finding.CurrentSeverityRank) <= threshold
		case "gt":
			return int(finding.CurrentSeverityRank) > threshold
		case "gte":
			return int(finding.CurrentSeverityRank) >= threshold
		}
	case "finding_kind":
		if cond.Operator == "eq" {
			return finding.FindingKind == cond.Value
		}
		if cond.Operator == "neq" {
			return finding.FindingKind != cond.Value
		}
	case "fingerprint":
		if cond.Operator == "eq" {
			return finding.Fingerprint == cond.Value
		}
		if cond.Operator == "neq" {
			return finding.Fingerprint != cond.Value
		}
	case "title_pattern":
		if cond.Operator == "contains" {
			return strings.Contains(finding.CurrentTitle, cond.Value)
		}
		if cond.Operator == "matches" {
			return finding.CurrentTitle == cond.Value
		}
	case "cve_id":
		if cond.Operator == "contains" {
			return strings.Contains(finding.Fingerprint, cond.Value)
		}
		if cond.Operator == "eq" {
			return finding.Fingerprint == cond.Value
		}
	}
	return false
}

func matchContexts(_ sqlc.Finding, _ []sqlc.WaiverContext) bool {
	return true
}

func matchTargets(finding sqlc.Finding, targets []sqlc.WaiverFindingTarget) bool {
	for _, t := range targets {
		if t.FindingID.Bytes == finding.ID.Bytes {
			return true
		}
	}
	return false
}
