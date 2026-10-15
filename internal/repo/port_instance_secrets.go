package repo

import (
	"context"

	"github.com/minh-tg/specht/internal/db/sqlc"
)

type pgInstanceSecretPort struct{ q *sqlc.Queries }

func (r *pgInstanceSecretPort) Ensure(ctx context.Context, name string, value []byte) ([]byte, error) {
	return r.q.EnsureInstanceSecret(ctx, sqlc.EnsureInstanceSecretParams{Name: name, Value: value})
}
