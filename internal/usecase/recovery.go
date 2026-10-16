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

// recoveryEmail normalizes the address a recovery command was given. An address
// with a rune that lower-cases differently in Go and in the database is refused
// like any other invalid address, rather than looked up under a guessed form.
func recoveryEmail(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", badCredentials("an email address is required")
	}
	email := auth.NormalizeEmail(raw)
	if email == "" {
		return "", badCredentials("invalid email address")
	}
	return email, nil
}

// ResetPasswordByEmail sets a new password for the account and ends every
// session it has. The store does both in one transaction under the account row
// lock, as in ChangePassword, and starts a new token generation. A deactivated
// account stays deactivated; the returned profile says so.
func (u *Usecases) ResetPasswordByEmail(ctx context.Context, email, password string) (*UserProfile, error) {
	email, err := recoveryEmail(email)
	if err != nil {
		return nil, err
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
	if err := u.deps.Stores.Users.ChangePasswordAndRevoke(ctx, user.ID, hash, ""); err != nil {
		return nil, fmt.Errorf("change password: %w", err)
	}
	profile := toUserProfile(user)
	return &profile, nil
}

// GrantAdminByEmail makes the account a global admin. Changing the role starts
// a new token generation, so a session the person already has picks it up at
// the next sign-in. An admin is left as is.
func (u *Usecases) GrantAdminByEmail(ctx context.Context, email string) (*UserProfile, error) {
	email, err := recoveryEmail(email)
	if err != nil {
		return nil, err
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
