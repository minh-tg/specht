package usecase

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
)

// ErrAccountNotFound means no account has the given email address.
var ErrAccountNotFound = errors.New("no account has that email address")

// The two methods below are the host-side recovery path for an instance whose
// only administrator has lost access. They take no caller identity and check
// no role: whoever can run the server binary against the database already holds
// every key, which is the whole point of the path. They are called only from
// the server's own subcommands and must never be reachable from an HTTP
// handler.

// ResetPasswordByEmail sets a new password for the account and ends every
// session it has. Refresh tokens are revoked before the write, as in
// ChangePassword, and the write starts a new token generation. A deactivated
// account stays deactivated; the returned profile says so.
func (u *Usecases) ResetPasswordByEmail(ctx context.Context, email, password string) (*UserProfile, error) {
	email = auth.NormalizeEmail(strings.TrimSpace(email))
	if email == "" {
		return nil, badCredentials("an email address is required")
	}
	user, err := u.recoveryTarget(ctx, email)
	if err != nil {
		return nil, err
	}
	if err := checkPassword(password, user.Email, derefStr(user.DisplayName)); err != nil {
		return nil, err
	}
	hash, err := u.deps.Passwords.Hash(password)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}
	if err := u.deps.Stores.RefreshTokens.RevokeAllForUser(ctx, user.ID); err != nil {
		return nil, fmt.Errorf("revoke refresh tokens: %w", err)
	}
	if err := u.deps.Stores.Users.SetPassword(ctx, user.ID, hash); err != nil {
		return nil, fmt.Errorf("set password: %w", err)
	}
	profile := toUserProfile(user)
	return &profile, nil
}

// GrantAdminByEmail makes the account a global admin. Changing the role starts
// a new token generation, so a session the person already has picks it up at
// the next sign-in. An admin is left as is.
func (u *Usecases) GrantAdminByEmail(ctx context.Context, email string) (*UserProfile, error) {
	email = auth.NormalizeEmail(strings.TrimSpace(email))
	if email == "" {
		return nil, badCredentials("an email address is required")
	}
	user, err := u.recoveryTarget(ctx, email)
	if err != nil {
		return nil, err
	}
	if user.Role != auth.RoleAdmin {
		user, err = u.deps.Stores.Users.ChangeRole(ctx, user.ID, auth.RoleAdmin)
		if err != nil {
			return nil, fmt.Errorf("grant admin: %w", err)
		}
	}
	profile := toUserProfile(user)
	return &profile, nil
}

// recoveryTarget finds the account a recovery command acts on and refuses the
// seeded system account.
func (u *Usecases) recoveryTarget(ctx context.Context, email string) (port.User, error) {
	user, err := u.deps.Stores.Users.GetByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, port.ErrNotFound) {
			return port.User{}, ErrAccountNotFound
		}
		return port.User{}, fmt.Errorf("look up account: %w", err)
	}
	if isSystemAccount(user.Email) {
		return port.User{}, ErrSystemAccount
	}
	return user, nil
}
