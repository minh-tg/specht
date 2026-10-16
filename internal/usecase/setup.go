package usecase

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
)

var (
	// ErrSetupClosed is returned when setup is attempted after an admin
	// exists, or on a server that offers no setup. Handlers answer 404.
	ErrSetupClosed = port.ErrSetupClosed
	// ErrSetupEmailTaken is returned when the setup address already belongs to
	// an account, for example one a stranger registered before the operator.
	ErrSetupEmailTaken = errors.New("that email address already belongs to an account")
	// ErrInvalidSetupToken is returned for a missing or wrong setup token.
	ErrInvalidSetupToken = errors.New("invalid setup token")
)

// SetupToken proves that whoever sets up a fresh server can read its logs or
// its environment. It is created at startup while no admin exists, shown
// once in the log, and forgotten when setup completes.
type SetupToken struct {
	mu    sync.Mutex
	token string
}

// minSetupTokenLength keeps an operator-chosen token out of guessing range.
const minSetupTokenLength = 16

// NewSetupToken wraps a given token, or generates a random one when value is
// empty. A given token shorter than minSetupTokenLength is refused.
func NewSetupToken(value string) (*SetupToken, error) {
	if value != "" && len(value) < minSetupTokenLength {
		return nil, fmt.Errorf("setup token must be at least %d characters", minSetupTokenLength)
	}
	if value == "" {
		raw := make([]byte, 24)
		if _, err := rand.Read(raw); err != nil {
			return nil, fmt.Errorf("generate setup token: %w", err)
		}
		value = base64.RawURLEncoding.EncodeToString(raw)
	}
	return &SetupToken{token: value}, nil
}

// Value returns the token, for showing it once at startup.
func (t *SetupToken) Value() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.token
}

// Verify reports whether candidate is the token, in constant time. It is false
// once the token has been cleared.
func (t *SetupToken) Verify(candidate string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.token == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(t.token), []byte(candidate)) == 1
}

// Clear forgets the token.
func (t *SetupToken) Clear() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.token = ""
}

// SetupRequired reports whether the server is waiting for its first admin: no
// active admin exists and a setup token is offered. Accounts that registered
// earlier do not count, so a stranger who signs up first cannot close setup.
func (u *Usecases) SetupRequired(ctx context.Context) (bool, error) {
	if u.deps.SetupToken == nil || u.deps.SetupToken.Value() == "" {
		return false, nil
	}
	count, err := u.deps.Stores.Users.CountAdmins(ctx)
	if err != nil {
		return false, fmt.Errorf("count admins: %w", err)
	}
	return count == 0, nil
}

// SetupInput is the first admin's account and the proof of access.
type SetupInput struct {
	Token       string
	Email       string
	Password    string
	DisplayName string
}

// Setup creates the first account as a global admin and signs it in. It works
// once: while no admin exists and with the token the server showed at
// startup. Two requests at once create one account.
func (u *Usecases) Setup(ctx context.Context, input SetupInput) (*AuthResponse, error) {
	required, err := u.SetupRequired(ctx)
	if err != nil {
		return nil, err
	}
	if !required {
		return nil, ErrSetupClosed
	}
	if !u.deps.SetupToken.Verify(input.Token) {
		// Another request may have finished setup after the check above: it
		// clears the token, so this caller's valid token stops verifying.
		// That caller lost a race and gets the closed answer, not a
		// wrong-token one.
		if stillRequired, err := u.SetupRequired(ctx); err == nil && !stillRequired {
			return nil, ErrSetupClosed
		}
		slog.Warn("setup: wrong setup token")
		return nil, ErrInvalidSetupToken
	}
	trimmedName := strings.TrimSpace(input.DisplayName)
	email, err := validateCredentials(input.Email, input.Password, trimmedName)
	if err != nil {
		return nil, err
	}
	hash, err := u.deps.Passwords.Hash(input.Password)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}
	var name *string
	if trimmedName != "" {
		name = &trimmedName
	}
	user, err := u.deps.Stores.Users.CreateFirstAdmin(ctx, email, name, hash)
	if errors.Is(err, port.ErrEmailTaken) {
		return nil, ErrSetupEmailTaken
	}
	if err != nil {
		return nil, err
	}
	u.deps.SetupToken.Clear()
	slog.Info("setup: first admin created", "user_id", user.ID, "email", auth.MaskEmail(email))

	token, err := u.issueAccessToken(ctx, user.ID, user.Email, auth.RoleAdmin)
	if err != nil {
		return nil, fmt.Errorf("create token: %w", err)
	}
	resp, err := u.createSession(ctx, user.ID, user.Email)
	if err != nil {
		return nil, err
	}
	resp.Token = token
	return resp, nil
}
