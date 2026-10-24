package repo

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minh-tg/specht/internal/db/sqlc"
)

// PostgresRevoker persists access-token revocations for all API replicas.
type PostgresRevoker struct {
	q *sqlc.Queries
}

func NewPostgresRevoker(pool *pgxpool.Pool) *PostgresRevoker {
	return &PostgresRevoker{q: sqlc.New(pool)}
}

func (r *PostgresRevoker) Revoke(ctx context.Context, jti string, exp time.Time) error {
	if jti == "" {
		return nil
	}
	err := r.q.RevokeAccessToken(ctx, sqlc.RevokeAccessTokenParams{
		Jti: jti, ExpiresAt: pgtype.Timestamptz{Time: exp, Valid: true},
	})
	if err != nil {
		return fmt.Errorf("store token revocation: %w", err)
	}
	return nil
}

// PruneExpired deletes at most 1000 expired revocations per lifecycle sweep.
func (r *PostgresRevoker) PruneExpired(ctx context.Context) (int64, error) {
	return r.q.PruneRevokedAccessTokens(ctx)
}

func (r *PostgresRevoker) IsRevoked(ctx context.Context, jti string) (bool, error) {
	revoked, err := r.q.IsAccessTokenRevoked(ctx, jti)
	if err != nil {
		return false, fmt.Errorf("check token revocation: %w", err)
	}
	return revoked, nil
}
