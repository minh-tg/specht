package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/usecase"
)

// changePasswordFixture drives Handler.ChangePassword and Handler.Login with
// one shared fake clock and one shared account delay, as the router wires them.
type changePasswordFixture struct {
	t     *testing.T
	h     *Handler
	now   time.Time
	calls atomic.Int64
	// current is the account's real password; the use case reports a wrong
	// one unless fail is set to another error.
	current string
	fail    error
}

func newChangePasswordFixture(t *testing.T) *changePasswordFixture {
	f := &changePasswordFixture{t: t, now: time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC), current: "right-password"}
	mock := &mockUsecases{
		changePasswordFn: func(_ context.Context, _, current, _ string) (*usecase.AuthResponse, error) {
			f.calls.Add(1)
			if f.fail != nil {
				return nil, f.fail
			}
			if current != f.current {
				return nil, usecase.ErrWrongPassword
			}
			return &usecase.AuthResponse{Token: "fresh"}, nil
		},
		loginFn: func(_ context.Context, _, password string) (*usecase.AuthResponse, error) {
			f.calls.Add(1)
			if password != f.current {
				return nil, usecase.ErrWrongPassword
			}
			return &usecase.AuthResponse{Token: "tok"}, nil
		},
	}
	f.h = NewHandler(mock)
	f.h.loginDelay = newLoginDelay()
	f.h.loginDelay.now = func() time.Time { return f.now }
	return f
}

// change sends PUT /me/password for the signed-in account from the given
// client address.
func (f *changePasswordFixture) change(ident *auth.Identity, from, current string) *httptest.ResponseRecorder {
	body := fmt.Sprintf(`{"current_password":%q,"new_password":"brand-new-password"}`, current)
	req := httptest.NewRequest("PUT", "/api/v1/me/password", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = from
	req = req.WithContext(auth.ContextWithIdentity(req.Context(), ident))
	w := httptest.NewRecorder()
	f.h.ChangePassword(w, req)
	return w
}

func (f *changePasswordFixture) login(email, password string) *httptest.ResponseRecorder {
	body := fmt.Sprintf(`{"email":%q,"password":%q}`, email, password)
	req := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.h.Login(w, req)
	return w
}

var victimIdentity = &auth.Identity{UserID: "user-1", Email: "Victim@Example.com"}

func TestChangePassword_WrongGuessesFromManyAddressesReachTheWait(t *testing.T) {
	f := newChangePasswordFixture(t)
	for i := range 3 {
		w := f.change(victimIdentity, fmt.Sprintf("203.0.113.%d:1", i), "guess")
		require.Equal(t, http.StatusBadRequest, w.Code, "guess %d is evaluated", i+1)
	}
	require.EqualValues(t, 3, f.calls.Load())

	// A fourth address cannot add a guess against the same account.
	w := f.change(victimIdentity, "[2001:db8:ffff::1]:1", "guess")
	require.Equal(t, http.StatusTooManyRequests, w.Code)
	code, _ := errorBody(t, w)
	assert.Equal(t, "too_many_attempts", code)
	assert.Equal(t, "1", w.Header().Get("Retry-After"))
	assert.EqualValues(t, 3, f.calls.Load(), "an attempt during the wait never reaches the password check")

	assert.Equal(t, http.StatusTooManyRequests, f.change(victimIdentity, "198.51.100.1:1", "right-password").Code,
		"even the right password is refused during the wait")

	f.now = f.now.Add(time.Second)
	assert.Equal(t, http.StatusOK, f.change(victimIdentity, "198.51.100.2:1", "right-password").Code,
		"after the wait the right password goes through")
}

func TestChangePassword_RightPasswordResetsTheCount(t *testing.T) {
	f := newChangePasswordFixture(t)
	f.change(victimIdentity, "203.0.113.1:1", "guess")
	f.change(victimIdentity, "203.0.113.2:1", "guess")
	require.Equal(t, http.StatusOK, f.change(victimIdentity, "203.0.113.3:1", "right-password").Code)

	f.change(victimIdentity, "203.0.113.4:1", "guess")
	f.change(victimIdentity, "203.0.113.5:1", "guess")
	assert.Equal(t, http.StatusBadRequest, f.change(victimIdentity, "203.0.113.6:1", "guess").Code,
		"the third failure since the success is still evaluated")
	assert.Equal(t, http.StatusTooManyRequests, f.change(victimIdentity, "203.0.113.7:1", "guess").Code)
}

func TestChangePassword_SharesTheCountWithLogin(t *testing.T) {
	t.Run("login failures count against a password change", func(t *testing.T) {
		f := newChangePasswordFixture(t)
		for range 3 {
			f.login("victim@example.com", "guess")
		}
		assert.Equal(t, http.StatusTooManyRequests, f.change(victimIdentity, "203.0.113.1:1", "right-password").Code)
	})
	t.Run("password change failures count against login", func(t *testing.T) {
		f := newChangePasswordFixture(t)
		for i := range 3 {
			f.change(victimIdentity, fmt.Sprintf("203.0.113.%d:1", i), "guess")
		}
		w := f.login("  VICTIM@example.com ", "right-password")
		assert.Equal(t, http.StatusTooManyRequests, w.Code)
		assert.Contains(t, w.Body.String(), "too_many_attempts")
	})
	t.Run("a mix of both reaches the wait", func(t *testing.T) {
		f := newChangePasswordFixture(t)
		f.login("victim@example.com", "guess")
		f.change(victimIdentity, "203.0.113.1:1", "guess")
		f.login("victim@example.com", "guess")
		assert.Equal(t, http.StatusTooManyRequests, f.change(victimIdentity, "203.0.113.2:1", "guess").Code)
	})
}

func TestChangePassword_RejectedNewPasswordsAreNotGuesses(t *testing.T) {
	f := newChangePasswordFixture(t)
	f.fail = usecase.ErrPasswordTooCommon
	for i := range 10 {
		require.Equal(t, http.StatusBadRequest, f.change(victimIdentity, "203.0.113.1:1", "right-password").Code, "attempt %d", i+1)
	}
	assert.EqualValues(t, 10, f.calls.Load(), "no wait started: the current password was never judged wrong")

	// Earlier real failures survive a rejected new password.
	f.fail = nil
	f.change(victimIdentity, "203.0.113.1:1", "guess")
	f.change(victimIdentity, "203.0.113.1:1", "guess")
	f.fail = usecase.ErrPasswordTooCommon
	f.change(victimIdentity, "203.0.113.1:1", "right-password")
	f.fail = nil
	assert.Equal(t, http.StatusBadRequest, f.change(victimIdentity, "203.0.113.1:1", "guess").Code, "third failure is evaluated")
	assert.Equal(t, http.StatusTooManyRequests, f.change(victimIdentity, "203.0.113.1:1", "guess").Code)
}

func TestChangePassword_RequestsThatNeverCheckAPasswordAreNotCounted(t *testing.T) {
	f := newChangePasswordFixture(t)
	for range 10 {
		require.Equal(t, http.StatusBadRequest, f.change(victimIdentity, "203.0.113.1:1", "").Code)
		f.change(&auth.Identity{UserID: "user-1", Email: "victim@example.com", IsAPIKey: true}, "203.0.113.1:1", "guess")
	}
	assert.EqualValues(t, 10, f.calls.Load(), "only the empty-password requests reached the use case")
	assert.Zero(t, f.h.loginDelay.accountCount(), "an empty password or an API key takes no allowance")
}

func TestChangePassword_AccountWithoutAnEmailInTheTokenIsKeyedByUserID(t *testing.T) {
	f := newChangePasswordFixture(t)
	ident := &auth.Identity{UserID: "user-9"}
	for range 3 {
		require.Equal(t, http.StatusBadRequest, f.change(ident, "203.0.113.1:1", "guess").Code)
	}
	assert.Equal(t, http.StatusTooManyRequests, f.change(ident, "203.0.113.2:1", "guess").Code)
}
