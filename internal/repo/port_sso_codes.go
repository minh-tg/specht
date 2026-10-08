package repo

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/minh-tg/specht/internal/db/sqlc"
	"github.com/minh-tg/specht/internal/port"
)

// pgSSOCodePort adapts SSOCodeStore.
type pgSSOCodePort struct{ q *sqlc.Queries }

func (r *pgSSOCodePort) Create(ctx context.Context, codeHash, userID, email, role string, expiresAt time.Time) error {
	uid, err := parseID(userID)
	if err != nil {
		return err
	}
	return r.q.CreateSSOCode(ctx, sqlc.CreateSSOCodeParams{
		CodeHash:  codeHash,
		UserID:    uid,
		Email:     email,
		Role:      role,
		ExpiresAt: pgtype.Timestamptz{Time: expiresAt, Valid: true},
	})
}

func (r *pgSSOCodePort) Consume(ctx context.Context, codeHash string, now time.Time) (port.SSOCode, error) {
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
		Email:     row.Email,
		Role:      row.Role,
		ExpiresAt: row.ExpiresAt.Time,
	}, nil
}
