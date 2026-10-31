package repo

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/minh-tg/specht/internal/auth"
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
	// A link its creator can no longer hand out looks like any dead link.
	ok, _, err := creatorMayGrant(ctx, r.q, row.ProjectID, row.CreatedBy, row.Role)
	if err != nil {
		return port.InviteView{}, err
	}
	if !ok {
		return port.InviteView{}, port.ErrNotFound
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

// creatorMayGrant reports whether the account that made an invite may still
// hand out its role on the project, by the rule CreateInvite applies. It share
// locks the rows the answer rests on, so inside a transaction a deactivation,
// demotion or removal of the creator waits until the transaction ends. The
// string names the reason when the answer is no. An invite without a creator
// (the account was deleted) is refused: no code path makes one on purpose.
func creatorMayGrant(ctx context.Context, q *sqlc.Queries, projectID, createdBy pgtype.UUID, role string) (bool, string, error) {
	if !createdBy.Valid {
		return false, "creator account is gone", nil
	}
	creator, err := q.LockInviteCreator(ctx, createdBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, "creator account is gone", nil
	}
	if err != nil {
		return false, "", err
	}
	grantor := auth.InviteGrantor{Active: !creator.DisabledAt.Valid, GlobalRole: creator.Role}
	direct, err := q.LockInviteCreatorMembership(ctx, sqlc.LockInviteCreatorMembershipParams{ProjectID: projectID, UserID: createdBy})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return false, "", err
	}
	grantor.DirectRole = direct
	teamRoles, err := q.LockInviteCreatorTeamRoles(ctx, sqlc.LockInviteCreatorTeamRolesParams{ProjectID: projectID, UserID: createdBy})
	if err != nil {
		return false, "", err
	}
	for _, tr := range teamRoles {
		if auth.RoleRank(tr) > auth.RoleRank(grantor.TeamRole) {
			grantor.TeamRole = tr
		}
	}
	if auth.MayGrantInvite(grantor, role) {
		return true, "", nil
	}
	if !grantor.Active {
		return false, "creator is deactivated", nil
	}
	return false, "creator no longer holds the authority to grant " + role, nil
}

// accept claims the invite, resolves the person and adds them to the project in
// one transaction. If any step fails the claim is rolled back and the link
// stays usable. The claim goes through only while the creator may still hand
// out the invite's role, checked under locks in the same transaction. The
// creator is locked before the invite row, the order a deactivation takes.
func (r *pgInvitePort) accept(ctx context.Context, tokenHash string, resolve func(q *sqlc.Queries, inv sqlc.Invite) (sqlc.User, error)) (port.AcceptedInvite, error) {
	var out port.AcceptedInvite
	err := r.withTx(ctx, func(q *sqlc.Queries) error {
		open, err := q.GetPendingInviteByHash(ctx, tokenHash)
		if errors.Is(err, pgx.ErrNoRows) {
			return port.ErrNotFound
		}
		if err != nil {
			return err
		}
		ok, reason, err := creatorMayGrant(ctx, q, open.ProjectID, open.CreatedBy, open.Role)
		if err != nil {
			return err
		}
		if !ok {
			slog.Info("invite refused: its creator cannot grant it", "invite_id", toUUID(open.ID), "project_id", toUUID(open.ProjectID), "role", open.Role, "reason", reason)
			return port.ErrNotFound
		}
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
