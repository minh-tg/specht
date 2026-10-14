package repo

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/minh-tg/specht/internal/db/sqlc"
	"github.com/minh-tg/specht/internal/port"
)

type pgPasswordResetPort struct {
	withTx func(ctx context.Context, fn func(q *sqlc.Queries) error) error
}

func (r *pgPasswordResetPort) Create(ctx context.Context, in port.NewPasswordReset) error {
	userID, err := parseID(in.UserID)
	if err != nil {
		return err
	}
	createdBy, err := parseID(in.CreatedBy)
	if err != nil {
		return err
	}
	return r.withTx(ctx, func(q *sqlc.Queries) error {
		if err := q.RevokePendingPasswordResets(ctx, userID); err != nil {
			return err
		}
		_, err := q.CreatePasswordReset(ctx, sqlc.CreatePasswordResetParams{
			TokenHash: in.TokenHash,
			UserID:    userID,
			CreatedBy: createdBy,
			ExpiresAt: timestamptzFromAny(in.ExpiresAt),
		})
		return err
	})
}

func (r *pgPasswordResetPort) Redeem(ctx context.Context, tokenHash, passwordHash string) (string, error) {
	var userID string
	err := r.withTx(ctx, func(q *sqlc.Queries) error {
		reset, err := q.ClaimPasswordReset(ctx, tokenHash)
		if errors.Is(err, pgx.ErrNoRows) {
			return port.ErrNotFound
		}
		if err != nil {
			return err
		}
		if err := q.RevokeUserRefreshTokens(ctx, reset.UserID); err != nil {
			return err
		}
		if err := q.SetUserPassword(ctx, sqlc.SetUserPasswordParams{
			ID:           reset.UserID,
			PasswordHash: pgtype.Text{String: passwordHash, Valid: true},
		}); err != nil {
			return err
		}
		userID = toUUID(reset.UserID)
		return nil
	})
	if err != nil {
		return "", err
	}
	return userID, nil
}
