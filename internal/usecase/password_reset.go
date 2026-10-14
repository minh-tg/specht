package usecase

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/minh-tg/specht/internal/port"
)

const (
	// resetLinkTTL is how long a password reset link works. The administrator hands it over by
	// hand, so it outlives a lunch break but not a weekend.
	resetLinkTTL    = 24 * time.Hour
	resetPathPrefix = "/reset/"
)

var (
	// ErrResetLinkInvalid covers every way a reset link can be dead: unknown, used, replaced by a
	// newer one or expired. They answer the same, so a link cannot be probed.
	ErrResetLinkInvalid = errors.New("this reset link is not valid")
	// ErrAccountDeactivated is returned when a link is requested for a deactivated account.
	ErrAccountDeactivated = errors.New("the account is deactivated")
)

// PasswordResetLinkResponse is a new link. The token is not stored, so the link is shown once.
type PasswordResetLinkResponse struct {
	Link      string `json:"link"`
	ExpiresAt string `json:"expires_at"`
}

// CreatePasswordResetLink issues a single-use link that lets the account's owner choose a new
// password. Only an instance administrator with a session can issue one. A new link retires the
// ones issued before it. Accounts that sign in elsewhere (no local password), deactivated accounts
// and the system account get none, so a reset never creates a way in that was not there before.
func (u *Usecases) CreatePasswordResetLink(ctx context.Context, userID string) (*PasswordResetLinkResponse, error) {
	ident, err := requireInstanceAdmin(ctx)
	if err != nil {
		return nil, err
	}
	id, err := validID(userID)
	if err != nil {
		return nil, err
	}
	user, err := u.deps.Stores.Users.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, port.ErrNotFound) {
			return nil, ErrAccountNotFound
		}
		return nil, fmt.Errorf("look up account: %w", err)
	}
	switch {
	case isSystemAccount(user.Email):
		return nil, ErrSystemAccount
	case user.DisabledAt != nil:
		return nil, ErrAccountDeactivated
	case user.PasswordHash == "":
		return nil, ErrNoLocalPassword
	}

	token, err := newInviteToken()
	if err != nil {
		return nil, err
	}
	expires := time.Now().Add(resetLinkTTL)
	if err := u.deps.Stores.PasswordReset.Create(ctx, port.NewPasswordReset{
		TokenHash: hashInviteToken(token),
		UserID:    user.ID,
		CreatedBy: ident.UserID,
		ExpiresAt: expires,
	}); err != nil {
		return nil, fmt.Errorf("create reset link: %w", err)
	}
	slog.Info("password reset link issued", "user_id", user.ID, "issued_by", ident.UserID)
	return &PasswordResetLinkResponse{
		Link:      resetPathPrefix + token,
		ExpiresAt: expires.Format(time.RFC3339),
	}, nil
}

// RedeemPasswordReset sets a new password through a link, ends every session of the account and
// uses the link up. The password is checked first, so a refused password leaves the link usable.
func (u *Usecases) RedeemPasswordReset(ctx context.Context, token, password string) error {
	if token == "" || len(token) > maxInviteTokenLength {
		return ErrResetLinkInvalid
	}
	if err := checkPasswordLength(password); err != nil {
		return err
	}
	hash, err := u.deps.Passwords.Hash(password)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	userID, err := u.deps.Stores.PasswordReset.Redeem(ctx, hashInviteToken(token), hash)
	if err != nil {
		if errors.Is(err, port.ErrNotFound) {
			return ErrResetLinkInvalid
		}
		return fmt.Errorf("redeem reset link: %w", err)
	}
	slog.Info("password reset through a link", "user_id", userID)
	return nil
}
