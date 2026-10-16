package repo

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/minh-tg/specht/internal/db/sqlc"
	"github.com/minh-tg/specht/internal/port"
)

// pgIdentityPort adapts IdentityStore.
type pgIdentityPort struct {
	q      *sqlc.Queries
	withTx func(ctx context.Context, fn func(q *sqlc.Queries) error) error
}

func (r *pgIdentityPort) GetBySubject(ctx context.Context, issuer, subject string) (port.UserIdentity, error) {
	row, err := r.q.GetUserIdentity(ctx, sqlc.GetUserIdentityParams{Issuer: issuer, Subject: subject})
	if err != nil {
		return port.UserIdentity{}, mappingErr(err)
	}
	return identityToPort(row), nil
}

func (r *pgIdentityPort) GetForUser(ctx context.Context, userID, issuer string) (port.UserIdentity, error) {
	uid, err := parseID(userID)
	if err != nil {
		return port.UserIdentity{}, err
	}
	row, err := r.q.GetUserIdentityForUser(ctx, sqlc.GetUserIdentityForUserParams{UserID: uid, Issuer: issuer})
	if err != nil {
		return port.UserIdentity{}, mappingErr(err)
	}
	return identityToPort(row), nil
}

func (r *pgIdentityPort) Link(ctx context.Context, userID, issuer, subject string, emailVerified bool) (port.UserIdentity, error) {
	uid, err := parseID(userID)
	if err != nil {
		return port.UserIdentity{}, err
	}
	row, err := r.q.CreateUserIdentity(ctx, sqlc.CreateUserIdentityParams{UserID: uid, Issuer: issuer, Subject: subject, EmailVerified: emailVerified})
	if err != nil {
		if isUniqueViolation(err) {
			return port.UserIdentity{}, port.ErrIdentityLinked
		}
		return port.UserIdentity{}, err
	}
	return identityToPort(row), nil
}

func (r *pgIdentityPort) LinkRevokingKeys(ctx context.Context, userID, issuer, subject string, emailVerified bool) (port.UserIdentity, []port.RevokedAPIKey, error) {
	uid, err := parseID(userID)
	if err != nil {
		return port.UserIdentity{}, nil, err
	}
	var linked port.UserIdentity
	var revoked []port.RevokedAPIKey
	err = r.withTx(ctx, func(q *sqlc.Queries) error {
		// Everything the previous holder of the address could still use ends
		// in this transaction. The account row is written first, the lock
		// order every retiring event and every redeem uses, so none of them
		// can slip a credential in between. The statements are idempotent, so
		// an account that never had a password goes through the same path.
		if err := q.ClearUserPassword(ctx, uid); err != nil {
			return err
		}
		if err := q.BumpUserTokenVersion(ctx, uid); err != nil {
			return err
		}
		if err := q.RevokeUserRefreshTokens(ctx, uid); err != nil {
			return err
		}
		if err := q.RevokePendingPasswordResets(ctx, uid); err != nil {
			return err
		}
		row, err := q.CreateUserIdentity(ctx, sqlc.CreateUserIdentityParams{UserID: uid, Issuer: issuer, Subject: subject, EmailVerified: emailVerified})
		if err != nil {
			return err
		}
		linked = identityToPort(row)
		keys, err := q.RevokeAPIKeysByCreator(ctx, uid)
		if err != nil {
			return err
		}
		for _, k := range keys {
			revoked = append(revoked, port.RevokedAPIKey{ID: toUUID(k.ID), ProjectSlug: k.ProjectSlug, Name: k.Name})
		}
		return nil
	})
	if err != nil {
		if isUniqueViolation(err) {
			return port.UserIdentity{}, nil, port.ErrIdentityLinked
		}
		return port.UserIdentity{}, nil, err
	}
	return linked, revoked, nil
}

func identityToPort(i sqlc.UserIdentity) port.UserIdentity {
	return port.UserIdentity{
		ID:        toUUID(i.ID),
		UserID:    toUUID(i.UserID),
		Issuer:    i.Issuer,
		Subject:   i.Subject,
		CreatedAt: i.CreatedAt.Time,
	}
}

// isUniqueViolation reports whether err is a Postgres unique-constraint
// violation (SQLSTATE 23505).
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
