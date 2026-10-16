package usecase

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
)

var (
	// ErrInvalidGlobalRole is returned for a global role other than admin or member.
	ErrInvalidGlobalRole = errors.New("role must be admin or member")
	// ErrLastGlobalAdmin is returned when a role change or deactivation would
	// leave the instance without an active admin.
	ErrLastGlobalAdmin = port.ErrLastGlobalAdmin
	// ErrCannotDeactivateSelf is returned when an admin deactivates their own account.
	ErrCannotDeactivateSelf = errors.New("you cannot deactivate your own account")
	// ErrSystemAccount is returned when a change targets the seeded system account.
	ErrSystemAccount = errors.New("the system account cannot be changed")
)

// SystemAccountEmail is the account the server seeds to act for things with no person behind
// them, such as an API key created before keys recorded their owner. Deactivating it would stop
// those keys, and it is nobody's login, so its role and state are not an admin's to change.
const SystemAccountEmail = "system@specht.local"

func isSystemAccount(email string) bool { return strings.EqualFold(email, SystemAccountEmail) }

// requireInstanceAdmin lets only a signed-in global admin through. The routes
// already require it; checking again keeps the use case safe if it is reached
// another way.
func requireInstanceAdmin(ctx context.Context) (*auth.Identity, error) {
	ident := auth.ContextIdentity(ctx)
	if ident == nil || ident.IsAPIKey || ident.Role != auth.RoleAdmin {
		return nil, ErrProjectAccessDenied
	}
	return ident, nil
}

// ChangeUserRole sets an account's global role (admin or member). Open sessions
// pick the new role up straight away, and the last active admin cannot be
// demoted.
func (u *Usecases) ChangeUserRole(ctx context.Context, userID, role string) (*UserProfile, error) {
	if _, err := requireInstanceAdmin(ctx); err != nil {
		return nil, err
	}
	if role != auth.RoleAdmin && role != auth.RoleMember {
		return nil, ErrInvalidGlobalRole
	}
	id, err := validID(userID)
	if err != nil {
		return nil, err
	}
	current, err := u.deps.Stores.Users.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}
	if isSystemAccount(current.Email) {
		return nil, ErrSystemAccount
	}
	if current.Role == role {
		profile := toUserProfile(current)
		return &profile, nil
	}
	user, err := u.deps.Stores.Users.ChangeRole(ctx, id, role)
	if err != nil {
		return nil, fmt.Errorf("change role: %w", err)
	}
	profile := toUserProfile(user)
	return &profile, nil
}

// RevokedAPIKey names an API key revoked together with its creator's account.
type RevokedAPIKey = port.RevokedAPIKey

// DeactivateUser ends an account's access: open sessions stop at their next
// request, refresh tokens are revoked, and the account cannot sign in again
// until it is reactivated. History and memberships stay. The API keys the
// account created are revoked in the same transaction and returned so the
// caller can record each one; reactivating the account does not bring them
// back. An admin cannot deactivate themselves, the last active admin cannot
// be deactivated, and the seeded system account cannot be deactivated at all.
func (u *Usecases) DeactivateUser(ctx context.Context, userID string) (*UserProfile, []RevokedAPIKey, error) {
	ident, err := requireInstanceAdmin(ctx)
	if err != nil {
		return nil, nil, err
	}
	id, err := validID(userID)
	if err != nil {
		return nil, nil, err
	}
	if strings.EqualFold(id, ident.UserID) {
		return nil, nil, ErrCannotDeactivateSelf
	}
	target, err := u.deps.Stores.Users.GetByID(ctx, id)
	if err != nil {
		return nil, nil, fmt.Errorf("get user: %w", err)
	}
	if isSystemAccount(target.Email) {
		return nil, nil, ErrSystemAccount
	}
	user, revokedKeys, err := u.deps.Stores.Users.Deactivate(ctx, id)
	if err != nil {
		return nil, nil, fmt.Errorf("deactivate user: %w", err)
	}
	if err := u.deps.Stores.RefreshTokens.RevokeAllForUser(ctx, id); err != nil {
		// The new token generation and the sign-in checks already stop the
		// account; revoking its refresh tokens is cleanup.
		slog.Error("deactivate user: revoke refresh tokens", "user_id", id, "error", err)
	}
	profile := toUserProfile(user)
	return &profile, revokedKeys, nil
}

// ReactivateUser lets a deactivated account sign in again.
func (u *Usecases) ReactivateUser(ctx context.Context, userID string) (*UserProfile, error) {
	if _, err := requireInstanceAdmin(ctx); err != nil {
		return nil, err
	}
	id, err := validID(userID)
	if err != nil {
		return nil, err
	}
	user, err := u.deps.Stores.Users.SetDisabled(ctx, id, false)
	if err != nil {
		return nil, fmt.Errorf("reactivate user: %w", err)
	}
	profile := toUserProfile(user)
	return &profile, nil
}
