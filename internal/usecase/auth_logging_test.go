package usecase

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
)

// captureLogs routes the default logger into a buffer for the test.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &buf
}

func TestRegister_DuplicateDoesNotLogTheFullEmail(t *testing.T) {
	logs := captureLogs(t)
	ur := &mockUserRepo{}
	ur.getByEmailFn = func(ctx context.Context, email string) (port.User, error) {
		return makeUser("00000000-0000-0000-0000-000000000041"), nil
	}
	uc := New(Deps{Stores: &port.Stores{Users: ur}})

	_, err := uc.Register(context.Background(), "taken@example.com", "password123")

	assert.ErrorIs(t, err, ErrRegistrationFailed)
	assert.NotContains(t, logs.String(), "taken@example.com", "account emails must not reach the logs")
	assert.Contains(t, logs.String(), auth.MaskEmail("taken@example.com"), "operators still get a recognisable trace")
}

func TestFindOrProvisionSSOUser_DoesNotLogTheFullEmail(t *testing.T) {
	logs := captureLogs(t)
	ur := &mockUserRepo{}
	ur.getByEmailFn = func(ctx context.Context, email string) (port.User, error) {
		return port.User{}, port.ErrNotFound
	}

	_, _, _, err := New(ssoTestDeps(ur)).FindOrProvisionSSOUser(
		context.Background(), auth.SSOClaims{Subject: "sub-9", Email: "mallory@evil.example"}, []string{"example.com"}, nil)

	assert.ErrorIs(t, err, auth.ErrSSONotProvisioned)
	assert.NotContains(t, logs.String(), "mallory@evil.example")
	assert.Contains(t, logs.String(), "sub-9", "the stable IdP subject is the identifier to log")
}
