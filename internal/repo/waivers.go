package repo

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minh-tg/specht/internal/db/sqlc"
)

type pgWaiverRepo struct {
	q    *sqlc.Queries
	pool *pgxpool.Pool
}

func (r *pgWaiverRepo) Create(ctx context.Context, arg sqlc.CreateWaiverParams) (sqlc.Waiver, error) {
	return r.q.CreateWaiver(ctx, arg)
}

func (r *pgWaiverRepo) List(ctx context.Context, projectID pgtype.UUID) ([]sqlc.Waiver, error) {
	return r.q.ListWaivers(ctx, projectID)
}

func (r *pgWaiverRepo) GetByID(ctx context.Context, id, projectID pgtype.UUID) (sqlc.Waiver, error) {
	return r.q.GetWaiver(ctx, sqlc.GetWaiverParams{ID: id, ProjectID: projectID})
}

func (r *pgWaiverRepo) Update(ctx context.Context, arg sqlc.UpdateWaiverParams) (sqlc.Waiver, error) {
	return r.q.UpdateWaiver(ctx, arg)
}

func (r *pgWaiverRepo) Delete(ctx context.Context, id, projectID pgtype.UUID) (sqlc.Waiver, error) {
	return r.q.DeleteWaiver(ctx, sqlc.DeleteWaiverParams{ID: id, ProjectID: projectID})
}

func (r *pgWaiverRepo) Toggle(ctx context.Context, id, projectID pgtype.UUID) (sqlc.Waiver, error) {
	return r.q.ToggleWaiver(ctx, sqlc.ToggleWaiverParams{ID: id, ProjectID: projectID})
}

// ToggleWithEvent changes a waiver's enabled state and records the matching
// audit event in one transaction. A failed event insert leaves the waiver
// unchanged rather than silently losing its audit history.
func (r *pgWaiverRepo) ToggleWithEvent(ctx context.Context, id, projectID pgtype.UUID, actorID string) (sqlc.Waiver, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return sqlc.Waiver{}, fmt.Errorf("begin tx: %w", err)
	}
	// Rollback is best-effort; after Commit the transaction is already closed.
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	q := sqlc.New(tx)
	waiver, err := q.ToggleWaiver(ctx, sqlc.ToggleWaiverParams{ID: id, ProjectID: projectID})
	if err != nil {
		return sqlc.Waiver{}, fmt.Errorf("toggle waiver: %w", err)
	}

	eventType := "enabled"
	if !waiver.Enabled {
		eventType = "disabled"
	}
	if _, err := q.CreateWaiverEvent(ctx, sqlc.CreateWaiverEventParams{
		WaiverID:  waiver.ID,
		EventType: eventType,
		ActorID:   textPtrFromString(&actorID),
		Metadata:  []byte(`{}`),
	}); err != nil {
		return sqlc.Waiver{}, fmt.Errorf("create waiver toggle event: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return sqlc.Waiver{}, fmt.Errorf("commit tx: %w", err)
	}
	return waiver, nil
}

func (r *pgWaiverRepo) ListActive(ctx context.Context, projectID pgtype.UUID) ([]sqlc.Waiver, error) {
	return r.q.ListActiveWaivers(ctx, projectID)
}

func (r *pgWaiverRepo) ListConditions(ctx context.Context, waiverID pgtype.UUID) ([]sqlc.WaiverCondition, error) {
	return r.q.ListWaiverConditions(ctx, waiverID)
}

func (r *pgWaiverRepo) ListConditionsByWaiverIDs(ctx context.Context, waiverIDs []pgtype.UUID) ([]sqlc.WaiverCondition, error) {
	return r.q.ListWaiverConditionsByWaiverIDs(ctx, waiverIDs)
}

func (r *pgWaiverRepo) CreateCondition(ctx context.Context, arg sqlc.CreateWaiverConditionParams) (sqlc.WaiverCondition, error) {
	return r.q.CreateWaiverCondition(ctx, arg)
}

func (r *pgWaiverRepo) DeleteConditions(ctx context.Context, waiverID pgtype.UUID) error {
	return r.q.DeleteWaiverConditions(ctx, waiverID)
}

func (r *pgWaiverRepo) ListContexts(ctx context.Context, waiverID pgtype.UUID) ([]sqlc.WaiverContext, error) {
	return r.q.ListWaiverContexts(ctx, waiverID)
}

func (r *pgWaiverRepo) ListContextsByWaiverIDs(ctx context.Context, waiverIDs []pgtype.UUID) ([]sqlc.WaiverContext, error) {
	return r.q.ListWaiverContextsByWaiverIDs(ctx, waiverIDs)
}

func (r *pgWaiverRepo) CreateContext(ctx context.Context, arg sqlc.CreateWaiverContextParams) (sqlc.WaiverContext, error) {
	return r.q.CreateWaiverContext(ctx, arg)
}

func (r *pgWaiverRepo) DeleteContexts(ctx context.Context, waiverID pgtype.UUID) error {
	return r.q.DeleteWaiverContexts(ctx, waiverID)
}

func (r *pgWaiverRepo) ListFindingTargets(ctx context.Context, waiverID pgtype.UUID) ([]sqlc.WaiverFindingTarget, error) {
	return r.q.ListWaiverFindingTargets(ctx, waiverID)
}

func (r *pgWaiverRepo) ListFindingTargetsByWaiverIDs(ctx context.Context, waiverIDs []pgtype.UUID) ([]sqlc.WaiverFindingTarget, error) {
	return r.q.ListWaiverFindingTargetsByWaiverIDs(ctx, waiverIDs)
}

func (r *pgWaiverRepo) CreateFindingTarget(ctx context.Context, arg sqlc.CreateWaiverFindingTargetParams) (sqlc.WaiverFindingTarget, error) {
	return r.q.CreateWaiverFindingTarget(ctx, arg)
}

func (r *pgWaiverRepo) DeleteFindingTargets(ctx context.Context, waiverID pgtype.UUID) error {
	return r.q.DeleteWaiverFindingTargets(ctx, waiverID)
}

func (r *pgWaiverRepo) CreateEvent(ctx context.Context, arg sqlc.CreateWaiverEventParams) (sqlc.WaiverEvent, error) {
	return r.q.CreateWaiverEvent(ctx, arg)
}

func (r *pgWaiverRepo) ListEvents(ctx context.Context, waiverID pgtype.UUID) ([]sqlc.WaiverEvent, error) {
	return r.q.ListWaiverEvents(ctx, waiverID)
}

// WaiverConditionInput, WaiverContextInput, and WaiverTargetInput describe
// child rows to attach to a waiver within the transactional create/update
// unit-of-work methods. WaiverID on the persisted rows is derived from the
// parent waiver, so the inputs do not carry it.
type WaiverConditionInput struct {
	Field    string
	Operator string
	Value    string
}

type WaiverContextInput struct {
	EnvironmentID pgtype.UUID
	TargetID      pgtype.UUID
	ArtifactID    pgtype.UUID
}

// WaiverTargetInput is a finding-target child row for the waiver unit-of-work methods.
type WaiverTargetInput struct {
	FindingID pgtype.UUID
}

// WaiverEventInput carries the audit event appended by the transactional
// unit-of-work methods.
type WaiverEventInput struct {
	EventType string
	ActorID   pgtype.Text
	Metadata  []byte
}

// CreateWaiverDetailsParams is the input to CreateWithDetails.
type CreateWaiverDetailsParams struct {
	ProjectID   pgtype.UUID
	Name        string
	Description string
	Enabled     bool
	ExpiresAt   pgtype.Timestamptz
	Conditions  []WaiverConditionInput
	Contexts    []WaiverContextInput
	Targets     []WaiverTargetInput
	Event       WaiverEventInput
}

// UpdateWaiverDetailsParams is the input to UpdateWithDetails. A nil slice
// for Conditions/Contexts/Targets leaves the corresponding child rows
// untouched; an empty (non-nil) slice clears them.
type UpdateWaiverDetailsParams struct {
	ID          pgtype.UUID
	ProjectID   pgtype.UUID
	Name        string
	Description string
	Conditions  []WaiverConditionInput
	Contexts    []WaiverContextInput
	Targets     []WaiverTargetInput
	Event       WaiverEventInput
}

// CreateWithDetails inserts a waiver together with its conditions, contexts,
// finding targets, and a creation event inside one transaction. The child
// rows are derived from the new waiver's ID.
func (r *pgWaiverRepo) CreateWithDetails(ctx context.Context, arg CreateWaiverDetailsParams) (sqlc.Waiver, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return sqlc.Waiver{}, fmt.Errorf("begin tx: %w", err)
	}
	// Rollback is best-effort; after Commit the transaction is already closed.
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	q := sqlc.New(tx)
	w, err := q.CreateWaiver(ctx, sqlc.CreateWaiverParams{
		ProjectID:   arg.ProjectID,
		Name:        arg.Name,
		Description: arg.Description,
		Enabled:     arg.Enabled,
		ExpiresAt:   arg.ExpiresAt,
	})
	if err != nil {
		return sqlc.Waiver{}, fmt.Errorf("create waiver: %w", err)
	}

	if err := createWaiverChildren(ctx, q, w.ID, arg.Conditions, arg.Contexts, arg.Targets); err != nil {
		return sqlc.Waiver{}, err
	}

	if _, err := q.CreateWaiverEvent(ctx, sqlc.CreateWaiverEventParams{
		WaiverID:  w.ID,
		EventType: arg.Event.EventType,
		ActorID:   arg.Event.ActorID,
		Metadata:  arg.Event.Metadata,
	}); err != nil {
		return sqlc.Waiver{}, fmt.Errorf("create waiver event: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return sqlc.Waiver{}, fmt.Errorf("commit tx: %w", err)
	}
	return w, nil
}

// UpdateWithDetails replaces the name/description and, when the given slices
// are non-nil, the full set of conditions/contexts/finding targets of a
// waiver inside one transaction, then appends an update event.
func (r *pgWaiverRepo) UpdateWithDetails(ctx context.Context, arg UpdateWaiverDetailsParams) (sqlc.Waiver, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return sqlc.Waiver{}, fmt.Errorf("begin tx: %w", err)
	}
	// Rollback is best-effort; after Commit the transaction is already closed.
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	q := sqlc.New(tx)
	w, err := updateWaiverRow(ctx, q, arg)
	if err != nil {
		return sqlc.Waiver{}, err
	}

	if err := replaceWaiverDetails(ctx, q, w.ID, arg); err != nil {
		return sqlc.Waiver{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return sqlc.Waiver{}, fmt.Errorf("commit tx: %w", err)
	}
	return w, nil
}

// updateWaiverRow merges the supplied name/description over the current
// waiver and writes the base row.
func updateWaiverRow(ctx context.Context, q *sqlc.Queries, arg UpdateWaiverDetailsParams) (sqlc.Waiver, error) {
	current, err := q.GetWaiver(ctx, sqlc.GetWaiverParams{ID: arg.ID, ProjectID: arg.ProjectID})
	if err != nil {
		return sqlc.Waiver{}, fmt.Errorf("get current waiver: %w", err)
	}
	name, desc := current.Name, current.Description
	if arg.Name != "" {
		name = arg.Name
	}
	if arg.Description != "" {
		desc = arg.Description
	}
	w, err := q.UpdateWaiver(ctx, sqlc.UpdateWaiverParams{
		ID:          arg.ID,
		ProjectID:   arg.ProjectID,
		Name:        name,
		Description: desc,
	})
	if err != nil {
		return sqlc.Waiver{}, fmt.Errorf("update waiver: %w", err)
	}
	return w, nil
}

// replaceWaiverDetails swaps the child rows supplied in the update and
// records the waiver event.
func replaceWaiverDetails(ctx context.Context, q *sqlc.Queries, waiverID pgtype.UUID, arg UpdateWaiverDetailsParams) error {
	if arg.Conditions != nil {
		if err := replaceWaiverConditions(ctx, q, waiverID, arg.Conditions); err != nil {
			return err
		}
	}
	if arg.Contexts != nil {
		if err := replaceWaiverContexts(ctx, q, waiverID, arg.Contexts); err != nil {
			return err
		}
	}
	if arg.Targets != nil {
		if err := replaceWaiverTargets(ctx, q, waiverID, arg.Targets); err != nil {
			return err
		}
	}
	if _, err := q.CreateWaiverEvent(ctx, sqlc.CreateWaiverEventParams{
		WaiverID:  waiverID,
		EventType: arg.Event.EventType,
		ActorID:   arg.Event.ActorID,
		Metadata:  arg.Event.Metadata,
	}); err != nil {
		return fmt.Errorf("create waiver event: %w", err)
	}
	return nil
}

// replaceWaiverConditions swaps the waiver's condition rows for the new set.
func replaceWaiverConditions(ctx context.Context, q *sqlc.Queries, waiverID pgtype.UUID, conditions []WaiverConditionInput) error {
	if err := q.DeleteWaiverConditions(ctx, waiverID); err != nil {
		return fmt.Errorf("delete conditions: %w", err)
	}
	for _, c := range conditions {
		if _, err := q.CreateWaiverCondition(ctx, sqlc.CreateWaiverConditionParams{
			WaiverID: waiverID,
			Field:    c.Field,
			Operator: c.Operator,
			Value:    c.Value,
		}); err != nil {
			return fmt.Errorf("create condition: %w", err)
		}
	}
	return nil
}

// replaceWaiverContexts swaps the waiver's context rows for the new set.
func replaceWaiverContexts(ctx context.Context, q *sqlc.Queries, waiverID pgtype.UUID, contexts []WaiverContextInput) error {
	if err := q.DeleteWaiverContexts(ctx, waiverID); err != nil {
		return fmt.Errorf("delete contexts: %w", err)
	}
	for _, c := range contexts {
		if _, err := q.CreateWaiverContext(ctx, sqlc.CreateWaiverContextParams{
			WaiverID:      waiverID,
			EnvironmentID: c.EnvironmentID,
			TargetID:      c.TargetID,
			ArtifactID:    c.ArtifactID,
		}); err != nil {
			return fmt.Errorf("create context: %w", err)
		}
	}
	return nil
}

// replaceWaiverTargets swaps the waiver's finding-target rows for the new set.
func replaceWaiverTargets(ctx context.Context, q *sqlc.Queries, waiverID pgtype.UUID, targets []WaiverTargetInput) error {
	if err := q.DeleteWaiverFindingTargets(ctx, waiverID); err != nil {
		return fmt.Errorf("delete targets: %w", err)
	}
	for _, t := range targets {
		if _, err := q.CreateWaiverFindingTarget(ctx, sqlc.CreateWaiverFindingTargetParams{
			WaiverID:  waiverID,
			FindingID: t.FindingID,
		}); err != nil {
			return fmt.Errorf("create finding target: %w", err)
		}
	}
	return nil
}

// createWaiverChildren inserts the condition/context/target child rows of a
// newly created waiver inside the caller's transaction.
func createWaiverChildren(ctx context.Context, q *sqlc.Queries, waiverID pgtype.UUID, conditions []WaiverConditionInput, contexts []WaiverContextInput, targets []WaiverTargetInput) error {
	for _, c := range conditions {
		if _, err := q.CreateWaiverCondition(ctx, sqlc.CreateWaiverConditionParams{
			WaiverID: waiverID,
			Field:    c.Field,
			Operator: c.Operator,
			Value:    c.Value,
		}); err != nil {
			return fmt.Errorf("create condition: %w", err)
		}
	}
	for _, c := range contexts {
		if _, err := q.CreateWaiverContext(ctx, sqlc.CreateWaiverContextParams{
			WaiverID:      waiverID,
			EnvironmentID: c.EnvironmentID,
			TargetID:      c.TargetID,
			ArtifactID:    c.ArtifactID,
		}); err != nil {
			return fmt.Errorf("create context: %w", err)
		}
	}
	for _, t := range targets {
		if _, err := q.CreateWaiverFindingTarget(ctx, sqlc.CreateWaiverFindingTargetParams{
			WaiverID:  waiverID,
			FindingID: t.FindingID,
		}); err != nil {
			return fmt.Errorf("create finding target: %w", err)
		}
	}
	return nil
}
