package repo

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/xMinhx/specht/internal/db/sqlc"
)

type Repos struct {
	Projects ProjectRepo
	Reports  ReportRepo
	Findings FindingRepo
	Users    UserRepo
	APIKeys  APIKeyRepo
}

func NewRepos(pool *pgxpool.Pool) *Repos {
	q := sqlc.New(pool)
	return &Repos{
		Projects: &pgProjectRepo{q: q},
		Reports:  &pgReportRepo{q: q},
		Findings: &pgFindingRepo{q: q},
		Users:    &pgUserRepo{q: q},
		APIKeys:  &pgAPIKeyRepo{q: q},
	}
}

type ProjectRepo interface {
	Create(ctx context.Context, arg sqlc.CreateProjectParams) (sqlc.Project, error)
	List(ctx context.Context) ([]sqlc.Project, error)
	GetBySlug(ctx context.Context, slug string) (sqlc.Project, error)
}

type ReportRepo interface {
	Create(ctx context.Context, arg CreateReportParams) (sqlc.Report, error)
	GetByID(ctx context.Context, id pgtype.UUID) (sqlc.Report, error)
	ListByProject(ctx context.Context, projectID pgtype.UUID, limit, offset int32) ([]sqlc.Report, error)
	UpdateStatus(ctx context.Context, id, projectID pgtype.UUID, status string, totalFindings int, errorMsg pgtype.Text) (sqlc.Report, error)
}

type UserRepo interface {
	Create(ctx context.Context, email string, displayName, passwordHash pgtype.Text) (sqlc.User, error)
	GetByEmail(ctx context.Context, email string) (sqlc.User, error)
	GetByID(ctx context.Context, id pgtype.UUID) (sqlc.User, error)
}

type APIKeyRepo interface {
	Create(ctx context.Context, arg sqlc.CreateAPIKeyParams) (sqlc.ApiKey, error)
	ListByProject(ctx context.Context, projectID pgtype.UUID) ([]sqlc.ListAPIKeysByProjectRow, error)
	GetByHash(ctx context.Context, keyHash string) (sqlc.ApiKey, error)
	Revoke(ctx context.Context, id, projectID pgtype.UUID) (sqlc.ApiKey, error)
}

type FindingRepo interface {
	Upsert(ctx context.Context, arg UpsertFindingParams) (sqlc.Finding, error)
	CreateOccurrence(ctx context.Context, arg CreateOccurrenceParams) (sqlc.FindingOccurrence, error)
	UpsertDimension(ctx context.Context, arg UpsertDimensionParams) (sqlc.FindingDimension, error)
	ListByProject(ctx context.Context, projectID pgtype.UUID, severities, states []string, limit, offset int32) ([]sqlc.Finding, error)
}
