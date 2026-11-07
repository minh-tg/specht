package usecase

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
)

// ErrNoResume is returned when a resume token cannot start a session: unknown,
// revoked, expired or for an account that changed. The answer is to sign in.
var ErrNoResume = errors.New("no session to resume")

// IssueResumeToken mints the token behind a browser's resume cookie, in the
// sign-in chain of a session it just issued. A tab keeps its session in its own
// storage, so a link opened in a new tab, such as the one a blocked pull request
// shows, starts with none. The cookie lets it continue this sign-in.
//
// The token is a refresh token row that never rotates: tabs resume concurrently,
// and a rotating token would read as a replay. It lasts one refresh period, like a
// tab's token, so a browser left idle signs in again, and each resume issues a new
// one. It is revoked with its chain, so signing out or a password change ends it.
func (u *Usecases) IssueResumeToken(ctx context.Context, refreshToken string) (string, error) {
	if refreshToken == "" {
		return "", errors.New("no session to resume from")
	}
	sum := sha256.Sum256([]byte(refreshToken))
	session, err := u.deps.Stores.RefreshTokens.GetByHash(ctx, hex.EncodeToString(sum[:]))
	if err != nil {
		return "", fmt.Errorf("find the session: %w", err)
	}
	user, err := u.deps.Stores.Users.GetByID(ctx, session.UserID)
	if err != nil {
		return "", fmt.Errorf("find the account: %w", err)
	}
	raw, err := u.deps.Tokens.CreateRefreshToken(user.ID)
	if err != nil {
		return "", fmt.Errorf("create resume token: %w", err)
	}
	rawSum := sha256.Sum256([]byte(raw))
	expiresAt := u.clock().Add(refreshTokenTTL)
	if end := session.FamilyStartedAt.Add(u.sessionMaxAge()); end.Before(expiresAt) {
		expiresAt = end
	}
	err = u.deps.Stores.RefreshTokens.CreateInChain(ctx, session.ID, port.NewRefreshToken{
		UserID:          user.ID,
		TokenHash:       hex.EncodeToString(rawSum[:]),
		ExpiresAt:       expiresAt,
		FamilyID:        session.FamilyID,
		FamilyStartedAt: session.FamilyStartedAt,
	}, user.TokenVersion)
	if err != nil {
		return "", fmt.Errorf("store resume token: %w", err)
	}
	return raw, nil
}

// ResumeSession starts a session for a new tab from a browser's resume token. It
// asks what a refresh asks, except that the token is not spent. The new tab gets
// its own refresh token in the same chain.
func (u *Usecases) ResumeSession(ctx context.Context, resumeToken string) (*AuthResponse, error) {
	if resumeToken == "" {
		return nil, ErrNoResume
	}
	sum := sha256.Sum256([]byte(resumeToken))
	stored, err := u.deps.Stores.RefreshTokens.GetByHash(ctx, hex.EncodeToString(sum[:]))
	if err != nil {
		return nil, ErrNoResume
	}
	now := u.clock()
	if stored.RevokedAt != nil || stored.ExpiresAt.Before(now) ||
		!now.Before(stored.FamilyStartedAt.Add(u.sessionMaxAge())) {
		return nil, ErrNoResume
	}
	user, err := u.deps.Stores.Users.GetByID(ctx, stored.UserID)
	if err != nil || user.DisabledAt != nil {
		return nil, ErrNoResume
	}

	resp, err := u.newSession(user.ID, user.Email, stored.FamilyID, stored.FamilyStartedAt, func(in port.NewRefreshToken) error {
		return u.deps.Stores.RefreshTokens.CreateInChain(ctx, stored.ID, in, user.TokenVersion)
	})
	if err != nil {
		slog.Warn("resume session refused", "user_id", user.ID, "error", err)
		return nil, ErrNoResume
	}
	token, err := u.deps.Tokens.CreateToken(user.ID, user.Email, auth.TokenRole(user.Role), user.TokenVersion)
	if err != nil {
		return nil, fmt.Errorf("create token: %w", err)
	}
	resp.Token = token
	return resp, nil
}
