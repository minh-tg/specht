package main

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

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

func captureBootstrapLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &buf
}

func TestBootstrapAdmins_PromotesProvenAccountsAndSkipsUnknown(t *testing.T) {
	logs := captureBootstrapLogs(t)
	store := &fakeUserStore{users: map[string]port.User{
		"ops@example.com":   {ID: "u-ops", Email: "ops@example.com", Role: "member", EmailProven: true},
		"admin@example.com": {ID: "u-admin", Email: "admin@example.com", Role: "admin"},
	}}
	stores := &port.Stores{Users: store}
	t.Setenv("ADMIN_EMAILS", "ops@example.com, ghost@example.com, admin@example.com")

	bootstrapAdmins(context.Background(), stores)

	if store.users["ops@example.com"].Role != "admin" {
		t.Fatalf("ops@example.com role = %q, want admin", store.users["ops@example.com"].Role)
	}
	if store.users["admin@example.com"].Role != "admin" {
		t.Fatalf("existing admin must stay admin")
	}
	out := logs.String()
	if strings.Contains(out, "level=WARN") || strings.Contains(out, "level=ERROR") {
		t.Fatalf("a proven account and an address with no account (it may sign up later through SSO) must not warn, got:\n%s", out)
	}
}

func TestBootstrapAdmins_MatchesEmailsCaseInsensitively(t *testing.T) {
	store := &fakeUserStore{users: map[string]port.User{
		"ops@example.com": {ID: "u-ops", Email: "ops@example.com", Role: "member", EmailProven: true},
	}}
	stores := &port.Stores{Users: store}
	t.Setenv("ADMIN_EMAILS", " Ops@Example.COM ")

	bootstrapAdmins(context.Background(), stores)

	if store.users["ops@example.com"].Role != "admin" {
		t.Fatalf("a mixed-case ADMIN_EMAILS entry must still promote the lowercase account, role = %q",
			store.users["ops@example.com"].Role)
	}
}

func TestBootstrapAdmins_DoesNotPromoteAnAccountThatNeverProvedTheAddress(t *testing.T) {
	logs := captureBootstrapLogs(t)
	store := &fakeUserStore{users: map[string]port.User{
		"ceo@example.com": {ID: "u-ceo", Email: "ceo@example.com", Role: "member"},
	}}
	stores := &port.Stores{Users: store}
	t.Setenv("ADMIN_EMAILS", "CEO@example.com, ceo@example.com")

	bootstrapAdmins(context.Background(), stores)

	if got := store.users["ceo@example.com"].Role; got != "member" {
		t.Fatalf("a password-registered account must stay a member, role = %q", got)
	}
	out := logs.String()
	if n := strings.Count(out, "level=WARN"); n != 1 {
		t.Fatalf("want exactly one warning per address, got %d:\n%s", n, out)
	}
	for _, want := range []string{"not promoted", "SSO", "first-run setup", "c***@example.com"} {
		if !strings.Contains(out, want) {
			t.Fatalf("the warning must contain %q, got:\n%s", want, out)
		}
	}
	if strings.Contains(out, "ceo@example.com") {
		t.Fatalf("the full address must not be logged, got:\n%s", out)
	}
}

func TestBootstrapAdmins_NeverPromotesADeactivatedAccount(t *testing.T) {
	logs := captureBootstrapLogs(t)
	disabled := time.Now()
	store := &fakeUserStore{users: map[string]port.User{
		"gone@example.com": {ID: "u-gone", Email: "gone@example.com", Role: "member", EmailProven: true, DisabledAt: &disabled},
	}}
	stores := &port.Stores{Users: store}
	t.Setenv("ADMIN_EMAILS", "gone@example.com")

	bootstrapAdmins(context.Background(), stores)

	if got := store.users["gone@example.com"].Role; got != "member" {
		t.Fatalf("a deactivated account must not be promoted, role = %q", got)
	}
	out := logs.String()
	if !strings.Contains(out, "level=WARN") || !strings.Contains(out, "deactivated") {
		t.Fatalf("the skip must be reported, got:\n%s", out)
	}
}

func TestBootstrapAdmins_EmptyNoop(t *testing.T) {
	store := &fakeUserStore{users: map[string]port.User{}}
	stores := &port.Stores{Users: store}
	t.Setenv("ADMIN_EMAILS", "")
	bootstrapAdmins(context.Background(), stores)
}
