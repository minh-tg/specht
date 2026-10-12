package repo

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/minh-tg/specht/internal/db/sqlc"
	"github.com/minh-tg/specht/internal/port"
)

type pgInvitePort struct {
	q      *sqlc.Queries
	withTx func(ctx context.Context, fn func(q *sqlc.Queries) error) error
}

func inviteToPort(r sqlc.Invite) port.Invite {
	inv := port.Invite{
		ID:        toUUID(r.ID),
		ProjectID: toUUID(r.ProjectID),
		Role:      r.Role,
		Email:     stringFromTextPtr(r.Email),
		CreatedAt: r.CreatedAt.Time,
		ExpiresAt: r.ExpiresAt.Time,
	}
	if r.CreatedBy.Valid {
		id := toUUID(r.CreatedBy)
		inv.CreatedBy = &id
	}
	return inv
}

func (r *pgInvitePort) Create(ctx context.Context, in port.NewInvite) (port.Invite, error) {
	projectID, err := parseID(in.ProjectID)
	if err != nil {
		return port.Invite{}, err
	}
	createdBy, err := parseID(in.CreatedBy)
	if err != nil {
		return port.Invite{}, err
	}
	row, err := r.q.CreateInvite(ctx, sqlc.CreateInviteParams{
		TokenHash: in.TokenHash,
		ProjectID: projectID,
		Role:      in.Role,
		Email:     textPtrFromString(in.Email),
		CreatedBy: createdBy,
		ExpiresAt: timestamptzFromAny(in.ExpiresAt),
	})
	if err != nil {
		return port.Invite{}, err
	}
	return inviteToPort(row), nil
}

func (r *pgInvitePort) CountPending(ctx context.Context, projectID string) (int64, error) {
	id, err := parseID(projectID)
	if err != nil {
		return 0, err
	}
	return r.q.CountPendingInvites(ctx, id)
}

func (r *pgInvitePort) ListPending(ctx context.Context, projectID string) ([]port.Invite, error) {
	id, err := parseID(projectID)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListPendingInvites(ctx, id)
	if err != nil {
		return nil, err
	}
	out := make([]port.Invite, len(rows))
	for i, row := range rows {
		out[i] = inviteToPort(sqlc.Invite{
			ID: row.ID, TokenHash: row.TokenHash, ProjectID: row.ProjectID, Role: row.Role,
			Email: row.Email, CreatedBy: row.CreatedBy, CreatedAt: row.CreatedAt, ExpiresAt: row.ExpiresAt,
		})
		out[i].CreatedByEmail = stringFromTextPtr(row.CreatedByEmail)
	}
	return out, nil
}

func (r *pgInvitePort) GetPending(ctx context.Context, projectID, id string) (port.Invite, error) {
	pid, err := parseID(projectID)
	if err != nil {
		return port.Invite{}, err
	}
	iid, err := parseID(id)
	if err != nil {
		return port.Invite{}, err
	}
	row, err := r.q.GetPendingInvite(ctx, sqlc.GetPendingInviteParams{ID: iid, ProjectID: pid})
	if err != nil {
		return port.Invite{}, mappingErr(err)
	}
	return inviteToPort(row), nil
}

func (r *pgInvitePort) Revoke(ctx context.Context, projectID, id string) (port.Invite, error) {
	pid, err := parseID(projectID)
	if err != nil {
		return port.Invite{}, err
	}
	iid, err := parseID(id)
	if err != nil {
		return port.Invite{}, err
	}
	row, err := r.q.RevokeInvite(ctx, sqlc.RevokeInviteParams{ID: iid, ProjectID: pid})
	if err != nil {
		return port.Invite{}, mappingErr(err)
	}
	return inviteToPort(row), nil
}

func (r *pgInvitePort) Lookup(ctx context.Context, tokenHash string) (port.InviteView, error) {
	row, err := r.q.LookupInvite(ctx, tokenHash)
	if err != nil {
		return port.InviteView{}, mappingErr(err)
	}
	return port.InviteView{ProjectName: row.ProjectName, Role: row.Role, Email: stringFromTextPtr(row.Email)}, nil
}

func (r *pgInvitePort) AcceptWithNewAccount(ctx context.Context, tokenHash string, account port.InviteeAccount) (port.AcceptedInvite, error) {
	return r.accept(ctx, tokenHash, func(q *sqlc.Queries, inv sqlc.Invite) (sqlc.User, error) {
		if inv.Email.Valid && !strings.EqualFold(inv.Email.String, account.Email) {
			return sqlc.User{}, port.ErrInviteEmailMismatch
		}
		user, err := q.CreateUser(ctx, sqlc.CreateUserParams{
			Email:        account.Email,
			DisplayName:  textPtrFromString(account.DisplayName),
			PasswordHash: textPtrFromString(&account.PasswordHash),
		})
		if err != nil {
			if isUniqueViolation(err) {
				return sqlc.User{}, port.ErrEmailTaken
			}
			return sqlc.User{}, err
		}
		return user, nil
	})
}

func (r *pgInvitePort) AcceptAsUser(ctx context.Context, tokenHash, userID string) (port.AcceptedInvite, error) {
	uid, err := parseID(userID)
	if err != nil {
		return port.AcceptedInvite{}, err
	}
	return r.accept(ctx, tokenHash, func(q *sqlc.Queries, inv sqlc.Invite) (sqlc.User, error) {
		user, err := q.GetUserByID(ctx, uid)
		if err != nil {
			return sqlc.User{}, mappingErr(err)
		}
		if inv.Email.Valid && !strings.EqualFold(inv.Email.String, user.Email) {
			return sqlc.User{}, port.ErrInviteEmailMismatch
		}
		return user, nil
	})
}

// accept claims the invite, resolves the person and adds them to the project in
// one transaction. If any step fails the claim is rolled back and the link
// stays usable.
func (r *pgInvitePort) accept(ctx context.Context, tokenHash string, resolve func(q *sqlc.Queries, inv sqlc.Invite) (sqlc.User, error)) (port.AcceptedInvite, error) {
	var out port.AcceptedInvite
	err := r.withTx(ctx, func(q *sqlc.Queries) error {
		inv, err := q.ClaimInvite(ctx, tokenHash)
		if errors.Is(err, pgx.ErrNoRows) {
			return port.ErrNotFound
		}
		if err != nil {
			return err
		}
		user, err := resolve(q, inv)
		if err != nil {
			return err
		}
		if err := q.SetInviteAcceptedBy(ctx, sqlc.SetInviteAcceptedByParams{ID: inv.ID, AcceptedBy: user.ID}); err != nil {
			return err
		}
		member, err := q.AddInvitedMember(ctx, sqlc.AddInvitedMemberParams{ProjectID: inv.ProjectID, UserID: user.ID, Role: inv.Role})
		if err != nil {
			return err
		}
		slug, err := q.GetProjectSlugByID(ctx, inv.ProjectID)
		if err != nil {
			return err
		}
		out = port.AcceptedInvite{
			User:        userToPort(user),
			ProjectID:   toUUID(inv.ProjectID),
			ProjectSlug: slug,
			Role:        member.Role,
			InviteID:    toUUID(inv.ID),
		}
		return nil
	})
	if err != nil {
		return port.AcceptedInvite{}, err
	}
	return out, nil
}
