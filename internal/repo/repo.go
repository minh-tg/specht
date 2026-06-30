package repo

import (
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/vulnserve/vulnserve/internal/db/sqlc"
)

type Repos struct {
	Projects *ProjectRepo
	Reports  *ReportRepo
	Findings *FindingRepo
}

func NewRepos(pool *pgxpool.Pool) *Repos {
	q := sqlc.New(pool)
	return &Repos{
		Projects: NewProjectRepo(q),
		Reports:  NewReportRepo(q),
		Findings: NewFindingRepo(q),
	}
}
