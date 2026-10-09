package repo

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/minh-tg/specht/internal/db/sqlc"
	"github.com/minh-tg/specht/internal/port"
)

// pgSSOCodePort adapts SSOCodeStore.
type pgSSOCodePort struct {
	q         *sqlc.Queries
	pruneMu   sync.Mutex
	nextPrune time.Time
}

// ssoCodePruneInterval bounds how often expired codes are swept. Expired codes
// are never accepted regardless, so the sweep only limits table growth.
const ssoCodePruneInterval = 30 * time.Second

// pruneExpired deletes expired codes at most once per ssoCodePruneInterval.
// A failed sweep is logged rather than dropped.
func (r *pgSSOCodePort) pruneExpired(ctx context.Context) {
	r.pruneMu.Lock()
	now := time.Now()
	due := now.After(r.nextPrune)
	if due {
		r.nextPrune = now.Add(ssoCodePruneInterval)
	}
	r.pruneMu.Unlock()
	if !due {
		return
	}
	if err := r.q.PruneSSOCodes(ctx); err != nil {
		slog.Warn("prune expired sso exchange codes", "error", err)
	}
}

func (r *pgSSOCodePort) Create(ctx context.Context, codeHash, userID string, expiresAt time.Time) error {
	r.pruneExpired(ctx)
	uid, err := parseID(userID)
	if err != nil {
		return err
	}
	return r.q.CreateSSOCode(ctx, sqlc.CreateSSOCodeParams{
		CodeHash:  codeHash,
		UserID:    uid,
		ExpiresAt: pgtype.Timestamptz{Time: expiresAt, Valid: true},
	})
}

func (r *pgSSOCodePort) Consume(ctx context.Context, codeHash string, now time.Time) (port.SSOCode, error) {
	r.pruneExpired(ctx)
	row, err := r.q.ConsumeSSOCode(ctx, sqlc.ConsumeSSOCodeParams{
		CodeHash:  codeHash,
		ExpiresAt: pgtype.Timestamptz{Time: now, Valid: true},
	})
	if err != nil {
		return port.SSOCode{}, mappingErr(err)
	}
	return port.SSOCode{
		CodeHash:  row.CodeHash,
		UserID:    toUUID(row.UserID),
		ExpiresAt: row.ExpiresAt.Time,
	}, nil
}
