package usecase

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/minh-tg/specht/internal/port"
)

// countingHasher records how much password work a code path performs. Equal
// work on every branch is what keeps response times from revealing whether
// an account exists.
type countingHasher struct {
	hashes   int
	verifies int
}

func (c *countingHasher) Hash(password string) (string, error) {
	c.hashes++
	return "hash:" + password, nil
}

func (c *countingHasher) Verify(password, encoded string) bool {
	c.verifies++
	return encoded == "hash:"+password
}

func TestLogin_SpendsOnePasswordCheckWhetherOrNotTheAccountExists(t *testing.T) {
	tests := []struct {
		name string
		user func() (port.User, error)
	}{
		{"unknown email", func() (port.User, error) { return port.User{}, port.ErrNotFound }},
		{"account without a password", func() (port.User, error) {
			u := makeUser("00000000-0000-0000-0000-000000000040")
			u.PasswordHash = ""
			return u, nil
		}},
		{"wrong password", func() (port.User, error) {
			u := makeUser("00000000-0000-0000-0000-000000000040")
			u.PasswordHash = "hash:something-else"
			return u, nil
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ur := &mockUserRepo{}
			ur.getByEmailFn = func(ctx context.Context, email string) (port.User, error) { return tc.user() }
			hasher := &countingHasher{}
			uc := New(Deps{Stores: &port.Stores{Users: ur}, Passwords: hasher})

			_, err := uc.Login(context.Background(), "someone@example.com", "password123")

			assert.EqualError(t, err, "invalid email or password")
			assert.Equal(t, 1, hasher.verifies, "every failed login must cost one password check")
		})
	}
}

func TestRegister_DuplicateEmailStillHashesThePassword(t *testing.T) {
	ur := &mockUserRepo{}
	ur.getByEmailFn = func(ctx context.Context, email string) (port.User, error) {
		return makeUser("00000000-0000-0000-0000-000000000041"), nil
	}
	hasher := &countingHasher{}
	uc := New(Deps{Stores: &port.Stores{Users: ur}, Passwords: hasher})

	_, err := uc.Register(context.Background(), "taken@example.com", "password123")

	assert.ErrorIs(t, err, ErrRegistrationFailed)
	assert.Equal(t, 1, hasher.hashes, "a duplicate must cost the same hashing as a new account")
}

func TestLogin_WithoutAHasherDoesNotPanic(t *testing.T) {
	ur := &mockUserRepo{}
	ur.getByEmailFn = func(ctx context.Context, email string) (port.User, error) {
		return port.User{}, port.ErrNotFound
	}
	uc := New(Deps{Stores: &port.Stores{Users: ur}})

	_, err := uc.Login(context.Background(), "someone@example.com", "password123")

	assert.EqualError(t, err, "invalid email or password")
}
