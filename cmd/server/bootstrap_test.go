package main

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/minh-tg/specht/internal/port"
)

type fakeUserStore struct {
	port.UserStore
	users map[string]port.User
}

func (f *fakeUserStore) GetByEmail(ctx context.Context, email string) (port.User, error) {
	u, ok := f.users[email]
	if !ok {
		return port.User{}, port.ErrNotFound
	}
	return u, nil
}

func (f *fakeUserStore) SetRole(ctx context.Context, userID, role string) (port.User, error) {
	for email, u := range f.users {
		if u.ID == userID {
			u.Role = role
			f.users[email] = u
			return u, nil
		}
	}
	return port.User{}, port.ErrNotFound
}

func TestBootstrapAdmins_PromotesKnownSkipsUnknown(t *testing.T) {
	store := &fakeUserStore{users: map[string]port.User{
		"ops@example.com":   {ID: "u-ops", Email: "ops@example.com", Role: "member"},
		"admin@example.com": {ID: "u-admin", Email: "admin@example.com", Role: "admin"},
	}}
	stores := &port.Stores{Users: store}
	t.Setenv("ADMIN_EMAILS", "ops@example.com, ghost@example.com, admin@example.com")

	bootstrapAdmins(context.Background(), stores, false)

	if store.users["ops@example.com"].Role != "admin" {
		t.Fatalf("ops@example.com role = %q, want admin", store.users["ops@example.com"].Role)
	}
	if store.users["admin@example.com"].Role != "admin" {
		t.Fatalf("existing admin must stay admin")
	}
}

func TestBootstrapAdmins_MatchesEmailsCaseInsensitively(t *testing.T) {
	store := &fakeUserStore{users: map[string]port.User{
		"ops@example.com": {ID: "u-ops", Email: "ops@example.com", Role: "member"},
	}}
	stores := &port.Stores{Users: store}
	t.Setenv("ADMIN_EMAILS", " Ops@Example.COM ")

	bootstrapAdmins(context.Background(), stores, false)

	if store.users["ops@example.com"].Role != "admin" {
		t.Fatalf("a mixed-case ADMIN_EMAILS entry must still promote the lowercase account, role = %q",
			store.users["ops@example.com"].Role)
	}
}

func TestBootstrapAdmins_EmptyNoop(t *testing.T) {
	store := &fakeUserStore{users: map[string]port.User{}}
	stores := &port.Stores{Users: store}
	t.Setenv("ADMIN_EMAILS", "")
	bootstrapAdmins(context.Background(), stores, false)
}

func captureBootstrapLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &buf
}

func TestBootstrapAdmins_UnregisteredAddressWithOpenSignupIsFlagged(t *testing.T) {
	logs := captureBootstrapLogs(t)
	stores := &port.Stores{Users: &fakeUserStore{users: map[string]port.User{}}}
	t.Setenv("ADMIN_EMAILS", "ops@example.com")

	bootstrapAdmins(context.Background(), stores, true)

	out := logs.String()
	if !strings.Contains(out, "level=ERROR") || !strings.Contains(out, "anyone can register") {
		t.Fatalf("an unclaimed admin address with open signup must be reported as claimable, got:\n%s", out)
	}
	if strings.Contains(out, "ops@example.com") {
		t.Fatalf("the full address must not be logged, got:\n%s", out)
	}
}

func TestBootstrapAdmins_UnregisteredAddressWithClosedSignupIsOnlyAWarning(t *testing.T) {
	logs := captureBootstrapLogs(t)
	stores := &port.Stores{Users: &fakeUserStore{users: map[string]port.User{}}}
	t.Setenv("ADMIN_EMAILS", "ops@example.com")

	bootstrapAdmins(context.Background(), stores, false)

	out := logs.String()
	if strings.Contains(out, "level=ERROR") || strings.Contains(out, "anyone can register") {
		t.Fatalf("closed signup cannot be raced, so no claimable-address alarm expected, got:\n%s", out)
	}
	if !strings.Contains(out, "unknown account") {
		t.Fatalf("the skip must still be logged, got:\n%s", out)
	}
}
