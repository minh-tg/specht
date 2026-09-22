package repo

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/minh-tg/specht/internal/db/sqlc"
	"github.com/minh-tg/specht/internal/port"
)

type pgWaiverPort struct{ inner *pgWaiverRepo }

func (r *pgWaiverPort) CreateWithDetails(ctx context.Context, input port.CreateWaiverInput) (port.Waiver, error) {
	pid, err := parseID(input.ProjectID)
	if err != nil {
		return port.Waiver{}, err
	}
	conds := make([]WaiverConditionInput, len(input.Conditions))
	for i, c := range input.Conditions {
		conds[i] = WaiverConditionInput{Field: c.Field, Operator: c.Operator, Value: c.Value}
	}
	ctxs := make([]WaiverContextInput, len(input.Contexts))
	for i, c := range input.Contexts {
		ctxs[i] = WaiverContextInput{
			EnvironmentID: uuidFromString(c.EnvironmentID),
			TargetID:      uuidFromString(c.TargetID),
			ArtifactID:    uuidFromString(c.ArtifactID),
		}
	}
	tgts := make([]WaiverTargetInput, len(input.Targets))
	for i, t := range input.Targets {
		tgts[i] = WaiverTargetInput{FindingID: uuidFromString(t.FindingID)}
	}
	row, err := r.inner.CreateWithDetails(ctx, CreateWaiverDetailsParams{
		ProjectID:   pid,
		Name:        input.Name,
		Description: input.Description,
		Enabled:     input.Enabled,
		Conditions:  conds,
		Contexts:    ctxs,
		Targets:     tgts,
		Event:       waiverEventInputToRepo(input.Event),
	})
	if err != nil {
		return port.Waiver{}, err
	}
	return waiverRowToPort(row), nil
}

func (r *pgWaiverPort) List(ctx context.Context, projectID string) ([]port.Waiver, error) {
	pid, err := parseID(projectID)
	if err != nil {
		return nil, err
	}
	rows, err := r.inner.List(ctx, pid)
	if err != nil {
		return nil, err
	}
	out := make([]port.Waiver, len(rows))
	for i, row := range rows {
		out[i] = waiverRowToPort(row)
	}
	return out, nil
}

func (r *pgWaiverPort) GetByID(ctx context.Context, id, projectID string) (port.Waiver, error) {
	wid, err := parseID(id)
	if err != nil {
		return port.Waiver{}, err
	}
	pid, err := parseID(projectID)
	if err != nil {
		return port.Waiver{}, err
	}
	row, err := r.inner.GetByID(ctx, wid, pid)
	if err != nil {
		return port.Waiver{}, mappingErr(err)
	}
	return waiverRowToPort(row), nil
}

func (r *pgWaiverPort) UpdateWithDetails(ctx context.Context, waiver port.Waiver, conditions *[]port.WaiverCondition, contexts *[]port.WaiverContext, targets *[]port.WaiverFindingTarget, event port.WaiverEventInput) (port.Waiver, error) {
	wid, err := parseID(waiver.ID)
	if err != nil {
		return port.Waiver{}, err
	}
	pid, err := parseID(waiver.ProjectID)
	if err != nil {
		return port.Waiver{}, err
	}
	arg := UpdateWaiverDetailsParams{
		ID:          wid,
		ProjectID:   pid,
		Name:        waiver.Name,
		Description: waiver.Description,
		Event:       waiverEventInputToRepo(event),
	}
	if conditions != nil {
		arg.Conditions = make([]WaiverConditionInput, len(*conditions))
		for i, c := range *conditions {
			arg.Conditions[i] = WaiverConditionInput{Field: c.Field, Operator: c.Operator, Value: c.Value}
		}
	}
	if contexts != nil {
		arg.Contexts = make([]WaiverContextInput, len(*contexts))
		for i, c := range *contexts {
			arg.Contexts[i] = WaiverContextInput{
				EnvironmentID: uuidFromString(c.EnvironmentID),
				TargetID:      uuidFromString(c.TargetID),
				ArtifactID:    uuidFromString(c.ArtifactID),
			}
		}
	}
	if targets != nil {
		arg.Targets = make([]WaiverTargetInput, len(*targets))
		for i, t := range *targets {
			arg.Targets[i] = WaiverTargetInput{FindingID: uuidFromString(t.FindingID)}
		}
	}
	row, err := r.inner.UpdateWithDetails(ctx, arg)
	if err != nil {
		return port.Waiver{}, mappingErr(err)
	}
	return waiverRowToPort(row), nil
}

func (r *pgWaiverPort) Delete(ctx context.Context, id, projectID string) error {
	wid, err := parseID(id)
	if err != nil {
		return err
	}
	pid, err := parseID(projectID)
	if err != nil {
		return err
	}
	if _, err := r.inner.Delete(ctx, wid, pid); err != nil {
		return mappingErr(err)
	}
	return nil
}

func (r *pgWaiverPort) Toggle(ctx context.Context, id, projectID string) (port.Waiver, error) {
	wid, err := parseID(id)
	if err != nil {
		return port.Waiver{}, err
	}
	pid, err := parseID(projectID)
	if err != nil {
		return port.Waiver{}, err
	}
	row, err := r.inner.Toggle(ctx, wid, pid)
	if err != nil {
		return port.Waiver{}, mappingErr(err)
	}
	return waiverRowToPort(row), nil
}

func (r *pgWaiverPort) ListActive(ctx context.Context, projectID string) ([]port.Waiver, error) {
	pid, err := parseID(projectID)
	if err != nil {
		return nil, err
	}
	rows, err := r.inner.ListActive(ctx, pid)
	if err != nil {
		return nil, err
	}
	out := make([]port.Waiver, len(rows))
	for i, row := range rows {
		out[i] = waiverRowToPort(row)
	}
	return out, nil
}

func (r *pgWaiverPort) ListConditions(ctx context.Context, waiverID string) ([]port.WaiverCondition, error) {
	wid, err := parseID(waiverID)
	if err != nil {
		return nil, err
	}
	rows, err := r.inner.ListConditions(ctx, wid)
	if err != nil {
		return nil, err
	}
	out := make([]port.WaiverCondition, len(rows))
	for i, row := range rows {
		out[i] = port.WaiverCondition{
			ID:       toUUID(row.ID),
			WaiverID: toUUID(row.WaiverID),
			Field:    row.Field,
			Operator: row.Operator,
			Value:    row.Value,
		}
	}
	return out, nil
}

func (r *pgWaiverPort) ListConditionsByWaiverIDs(ctx context.Context, waiverIDs []string) ([]port.WaiverCondition, error) {
	uuids := make([]pgtype.UUID, 0, len(waiverIDs))
	for _, id := range waiverIDs {
		wid, err := parseID(id)
		if err != nil {
			return nil, err
		}
		uuids = append(uuids, wid)
	}
	rows, err := r.inner.ListConditionsByWaiverIDs(ctx, uuids)
	if err != nil {
		return nil, err
	}
	out := make([]port.WaiverCondition, len(rows))
	for i, row := range rows {
		out[i] = port.WaiverCondition{
			ID:       toUUID(row.ID),
			WaiverID: toUUID(row.WaiverID),
			Field:    row.Field,
			Operator: row.Operator,
			Value:    row.Value,
		}
	}
	return out, nil
}

func (r *pgWaiverPort) ListContexts(ctx context.Context, waiverID string) ([]port.WaiverContext, error) {
	wid, err := parseID(waiverID)
	if err != nil {
		return nil, err
	}
	rows, err := r.inner.ListContexts(ctx, wid)
	if err != nil {
		return nil, err
	}
	out := make([]port.WaiverContext, len(rows))
	for i, row := range rows {
		out[i] = port.WaiverContext{
			ID:            toUUID(row.ID),
			WaiverID:      toUUID(row.WaiverID),
			EnvironmentID: toUUID(row.EnvironmentID),
			TargetID:      toUUID(row.TargetID),
			ArtifactID:    toUUID(row.ArtifactID),
		}
	}
	return out, nil
}

func (r *pgWaiverPort) ListContextsByWaiverIDs(ctx context.Context, waiverIDs []string) ([]port.WaiverContext, error) {
	uuids := make([]pgtype.UUID, 0, len(waiverIDs))
	for _, id := range waiverIDs {
		wid, err := parseID(id)
		if err != nil {
			return nil, err
		}
		uuids = append(uuids, wid)
	}
	rows, err := r.inner.ListContextsByWaiverIDs(ctx, uuids)
	if err != nil {
		return nil, err
	}
	out := make([]port.WaiverContext, len(rows))
	for i, row := range rows {
		out[i] = port.WaiverContext{
			ID:            toUUID(row.ID),
			WaiverID:      toUUID(row.WaiverID),
			EnvironmentID: toUUID(row.EnvironmentID),
			TargetID:      toUUID(row.TargetID),
			ArtifactID:    toUUID(row.ArtifactID),
		}
	}
	return out, nil
}

func (r *pgWaiverPort) ListFindingTargets(ctx context.Context, waiverID string) ([]port.WaiverFindingTarget, error) {
	wid, err := parseID(waiverID)
	if err != nil {
		return nil, err
	}
	rows, err := r.inner.ListFindingTargets(ctx, wid)
	if err != nil {
		return nil, err
	}
	out := make([]port.WaiverFindingTarget, len(rows))
	for i, row := range rows {
		out[i] = port.WaiverFindingTarget{
			ID:        toUUID(row.ID),
			WaiverID:  toUUID(row.WaiverID),
			FindingID: toUUID(row.FindingID),
		}
	}
	return out, nil
}

func (r *pgWaiverPort) ListFindingTargetsByWaiverIDs(ctx context.Context, waiverIDs []string) ([]port.WaiverFindingTarget, error) {
	uuids := make([]pgtype.UUID, 0, len(waiverIDs))
	for _, id := range waiverIDs {
		wid, err := parseID(id)
		if err != nil {
			return nil, err
		}
		uuids = append(uuids, wid)
	}
	rows, err := r.inner.ListFindingTargetsByWaiverIDs(ctx, uuids)
	if err != nil {
		return nil, err
	}
	out := make([]port.WaiverFindingTarget, len(rows))
	for i, row := range rows {
		out[i] = port.WaiverFindingTarget{
			ID:        toUUID(row.ID),
			WaiverID:  toUUID(row.WaiverID),
			FindingID: toUUID(row.FindingID),
		}
	}
	return out, nil
}

func (r *pgWaiverPort) CreateEvent(ctx context.Context, event port.WaiverEvent) error {
	wid, err := parseID(event.WaiverID)
	if err != nil {
		return err
	}
	_, err = r.inner.CreateEvent(ctx, sqlc.CreateWaiverEventParams{
		WaiverID:  wid,
		EventType: event.EventType,
		ActorID:   textPtrFromString(&event.ActorID),
		Metadata:  event.Metadata,
	})
	return err
}

func (r *pgWaiverPort) ListEvents(ctx context.Context, waiverID string) ([]port.WaiverEvent, error) {
	wid, err := parseID(waiverID)
	if err != nil {
		return nil, err
	}
	rows, err := r.inner.ListEvents(ctx, wid)
	if err != nil {
		return nil, err
	}
	out := make([]port.WaiverEvent, len(rows))
	for i, row := range rows {
		actorID := ""
		if row.ActorID.Valid {
			actorID = row.ActorID.String
		}
		out[i] = port.WaiverEvent{
			ID:        toUUID(row.ID),
			WaiverID:  toUUID(row.WaiverID),
			EventType: row.EventType,
			ActorID:   actorID,
			Metadata:  row.Metadata,
			CreatedAt: row.CreatedAt.Time,
		}
	}
	return out, nil
}

func waiverEventInputToRepo(e port.WaiverEventInput) WaiverEventInput {
	return WaiverEventInput{
		EventType: e.EventType,
		ActorID:   textPtrFromString(e.ActorID),
		Metadata:  e.Metadata,
	}
}

func waiverRowToPort(w sqlc.Waiver) port.Waiver {
	return port.Waiver{
		ID:          toUUID(w.ID),
		ProjectID:   toUUID(w.ProjectID),
		Name:        w.Name,
		Description: w.Description,
		Enabled:     w.Enabled,
		CreatedAt:   w.CreatedAt.Time,
		UpdatedAt:   w.UpdatedAt.Time,
	}
}
