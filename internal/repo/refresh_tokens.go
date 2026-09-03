package repo

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/xMinhx/specht/internal/db/sqlc"
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

func (r *pgRefreshTokenRepo) Revoke(ctx context.Context, id pgtype.UUID) (sqlc.RefreshToken, error) {
	return r.q.RevokeRefreshToken(ctx, id)
}

func (r *pgRefreshTokenRepo) RevokeAllForUser(ctx context.Context, userID pgtype.UUID) error {
	return r.q.RevokeUserRefreshTokens(ctx, userID)
}

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
