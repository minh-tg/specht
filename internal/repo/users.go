package repo

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/xMinhx/specht/internal/db/sqlc"
)

type pgUserRepo struct {
	q *sqlc.Queries
}

func (r *pgUserRepo) Create(ctx context.Context, email string, displayName, passwordHash pgtype.Text) (sqlc.User, error) {
	return r.q.CreateUser(ctx, sqlc.CreateUserParams{
		Email:        email,
		DisplayName:  displayName,
		PasswordHash: passwordHash,
	})
}

func (r *pgUserRepo) GetByEmail(ctx context.Context, email string) (sqlc.User, error) {
	return r.q.GetUserByEmail(ctx, email)
}

func (r *pgUserRepo) GetByID(ctx context.Context, id pgtype.UUID) (sqlc.User, error) {
	return r.q.GetUserByID(ctx, id)
}
