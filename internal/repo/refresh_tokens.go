package repo

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/xMinhx/specht/internal/db/sqlc"
	"github.com/xMinhx/specht/internal/port"
)

// RefreshTokenRepo persists user refresh tokens.
type RefreshTokenRepo interface {
	Create(ctx context.Context, userID pgtype.UUID, tokenHash string, expiresAt time.Time) (sqlc.RefreshToken, error)
	GetByHash(ctx context.Context, tokenHash string) (sqlc.RefreshToken, error)
	Revoke(ctx context.Context, id pgtype.UUID) (sqlc.RefreshToken, error)
	RevokeAllForUser(ctx context.Context, userID pgtype.UUID) error
}

type pgRefreshTokenRepo struct {
	q *sqlc.Queries
}

func (r *pgRefreshTokenRepo) Create(ctx context.Context, userID pgtype.UUID, tokenHash string, expiresAt time.Time) (sqlc.RefreshToken, error) {
	return r.q.CreateRefreshToken(ctx, sqlc.CreateRefreshTokenParams{
		UserID:    userID,
		TokenHash: tokenHash,
		ExpiresAt: pgtype.Timestamptz{Time: expiresAt, Valid: true},
	})
}

func (r *pgRefreshTokenRepo) GetByHash(ctx context.Context, tokenHash string) (sqlc.RefreshToken, error) {
	return r.q.GetRefreshTokenByHash(ctx, tokenHash)
}

// Revoke retires a refresh token exactly once (M3 compare-and-swap): the
// guarded UPDATE matches only unrevoked rows, so a second call finds no row.
// pgx reports that as ErrNoRows; it is translated to port.ErrNotFound so
// callers detect replays without importing pgx.
func (r *pgRefreshTokenRepo) Revoke(ctx context.Context, id pgtype.UUID) (sqlc.RefreshToken, error) {
	row, err := r.q.RevokeRefreshToken(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return sqlc.RefreshToken{}, port.ErrNotFound
		}
		return sqlc.RefreshToken{}, err
	}
	return row, nil
}

func (r *pgRefreshTokenRepo) RevokeAllForUser(ctx context.Context, userID pgtype.UUID) error {
	return r.q.RevokeUserRefreshTokens(ctx, userID)
}
