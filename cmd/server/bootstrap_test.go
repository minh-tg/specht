package main

import (
	"context"
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

	bootstrapAdmins(context.Background(), stores)

	if store.users["ops@example.com"].Role != "admin" {
		t.Fatalf("ops@example.com role = %q, want admin", store.users["ops@example.com"].Role)
	}
	if store.users["admin@example.com"].Role != "admin" {
		t.Fatalf("existing admin must stay admin")
	}
}

func TestBootstrapAdmins_EmptyNoop(t *testing.T) {
	store := &fakeUserStore{users: map[string]port.User{}}
	stores := &port.Stores{Users: store}
	t.Setenv("ADMIN_EMAILS", "")
	bootstrapAdmins(context.Background(), stores)
}
