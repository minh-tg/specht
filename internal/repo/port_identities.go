package repo

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/minh-tg/specht/internal/db/sqlc"
	"github.com/minh-tg/specht/internal/port"
)

// pgIdentityPort adapts IdentityStore.
type pgIdentityPort struct{ q *sqlc.Queries }

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

func (r *pgIdentityPort) Link(ctx context.Context, userID, issuer, subject string) (port.UserIdentity, error) {
	uid, err := parseID(userID)
	if err != nil {
		return port.UserIdentity{}, err
	}
	row, err := r.q.CreateUserIdentity(ctx, sqlc.CreateUserIdentityParams{UserID: uid, Issuer: issuer, Subject: subject})
	if err != nil {
		if isUniqueViolation(err) {
			return port.UserIdentity{}, port.ErrIdentityLinked
		}
		return port.UserIdentity{}, err
	}
	return identityToPort(row), nil
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
