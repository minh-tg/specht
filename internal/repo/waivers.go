package repo

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/xMinhx/specht/internal/db/sqlc"
)

type pgWaiverRepo struct {
	q *sqlc.Queries
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

func (r *pgWaiverRepo) ListActive(ctx context.Context, projectID pgtype.UUID) ([]sqlc.Waiver, error) {
	return r.q.ListActiveWaivers(ctx, projectID)
}

func (r *pgWaiverRepo) ListConditions(ctx context.Context, waiverID pgtype.UUID) ([]sqlc.WaiverCondition, error) {
	return r.q.ListWaiverConditions(ctx, waiverID)
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

func (r *pgWaiverRepo) CreateContext(ctx context.Context, arg sqlc.CreateWaiverContextParams) (sqlc.WaiverContext, error) {
	return r.q.CreateWaiverContext(ctx, arg)
}

func (r *pgWaiverRepo) DeleteContexts(ctx context.Context, waiverID pgtype.UUID) error {
	return r.q.DeleteWaiverContexts(ctx, waiverID)
}

func (r *pgWaiverRepo) ListFindingTargets(ctx context.Context, waiverID pgtype.UUID) ([]sqlc.WaiverFindingTarget, error) {
	return r.q.ListWaiverFindingTargets(ctx, waiverID)
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
