package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/usecase"
)

// loginDelayFixture drives Handler.Login directly with a fake clock, so the
// waits are exact and no test sleeps.
type loginDelayFixture struct {
	t       *testing.T
	h       *Handler
	now     time.Time
	calls   atomic.Int64
	success atomic.Bool // when set the use case accepts the password
}

func newLoginDelayFixture(t *testing.T) *loginDelayFixture {
	f := &loginDelayFixture{t: t, now: time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)}
	mock := &mockUsecases{loginFn: func(context.Context, string, string) (*usecase.AuthResponse, error) {
		f.calls.Add(1)
		if f.success.Load() {
			return &usecase.AuthResponse{Token: "tok"}, nil
		}
		return nil, errors.New("invalid email or password")
	}}
	f.h = NewHandler(mock)
	f.h.loginDelay = newLoginDelay()
	f.h.loginDelay.now = func() time.Time { return f.now }
	return f
}

func (f *loginDelayFixture) login(email string) *httptest.ResponseRecorder {
	body := fmt.Sprintf(`{"email":%q,"password":"guess"}`, email)
	req := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.h.Login(w, req)
	return w
}

func (f *loginDelayFixture) advance(d time.Duration) { f.now = f.now.Add(d) }

func TestLoginDelay_ThirdFailureStartsTheWaitAndBlockedAttemptsAreNotEvaluated(t *testing.T) {
	f := newLoginDelayFixture(t)
	for i := range 3 {
		require.Equal(t, http.StatusUnauthorized, f.login("victim@example.com").Code, "attempt %d is evaluated", i+1)
	}
	require.EqualValues(t, 3, f.calls.Load())

	w := f.login("victim@example.com")
	require.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.Contains(t, w.Body.String(), "too_many_attempts")
	assert.Equal(t, "1", w.Header().Get("Retry-After"))
	assert.EqualValues(t, 3, f.calls.Load(), "an attempt during the wait never reaches the password check")

	f.success.Store(true)
	assert.Equal(t, http.StatusTooManyRequests, f.login("victim@example.com").Code,
		"even the right password is refused during the wait")
	assert.EqualValues(t, 3, f.calls.Load())
}

func TestLoginDelay_WaitDoublesAndStopsAtSixtySeconds(t *testing.T) {
	f := newLoginDelayFixture(t)
	for range 3 {
		f.login("victim@example.com")
	}
	want := []int{1, 2, 4, 8, 16, 32, 60, 60, 60}
	for i, secs := range want {
		w := f.login("victim@example.com")
		require.Equal(t, http.StatusTooManyRequests, w.Code, "step %d", i)
		require.Equal(t, strconv.Itoa(secs), w.Header().Get("Retry-After"), "step %d", i)

		f.advance(time.Duration(secs) * time.Second)
		require.Equal(t, http.StatusUnauthorized, f.login("victim@example.com").Code,
			"step %d: the attempt after the wait is evaluated again", i)
	}
}

func TestLoginDelay_RetryAfterCountsDownDuringTheWait(t *testing.T) {
	f := newLoginDelayFixture(t)
	for range 3 {
		f.login("victim@example.com")
	}
	f.login("victim@example.com") // 429
	f.advance(1 * time.Second)
	f.login("victim@example.com") // 4th evaluated, wait is now 2s
	f.advance(500 * time.Millisecond)
	assert.Equal(t, "2", f.login("victim@example.com").Header().Get("Retry-After"), "1.5s left rounds up")
}

func TestLoginDelay_EmailsAreNormalizedAndUnknownAccountsCountTheSame(t *testing.T) {
	f := newLoginDelayFixture(t) // the use case rejects every email alike, as for unknown accounts
	f.login("Victim@Example.com")
	f.login("  victim@example.com ")
	f.login("VICTIM@EXAMPLE.COM")
	assert.Equal(t, http.StatusTooManyRequests, f.login("victim@example.com").Code,
		"spelling variants share one counter")

	w := f.login("nobody-registered@example.com")
	assert.Equal(t, http.StatusUnauthorized, w.Code, "another email has its own counter")
}

func TestLoginDelay_SuccessResetsTheCounter(t *testing.T) {
	f := newLoginDelayFixture(t)
	f.login("victim@example.com")
	f.login("victim@example.com")
	f.success.Store(true)
	require.Equal(t, http.StatusOK, f.login("victim@example.com").Code)
	f.success.Store(false)

	f.login("victim@example.com")
	f.login("victim@example.com")
	assert.Equal(t, http.StatusUnauthorized, f.login("victim@example.com").Code, "the third failure since the success is still evaluated")
	assert.Equal(t, http.StatusTooManyRequests, f.login("victim@example.com").Code)
}

func TestLoginDelay_CounterDecaysAfterFifteenQuietMinutes(t *testing.T) {
	f := newLoginDelayFixture(t)
	for range 5 {
		f.login("victim@example.com")
		f.advance(time.Minute) // spaced out so no attempt meets a wait
	}
	f.advance(loginDelayDecay - time.Minute)
	f.advance(time.Second)
	f.login("victim@example.com")
	f.login("victim@example.com")
	assert.Equal(t, http.StatusUnauthorized, f.login("victim@example.com").Code,
		"two failures after the decay start from zero, so the third is evaluated")
	assert.Equal(t, http.StatusTooManyRequests, f.login("victim@example.com").Code)
}

func TestLoginDelay_MissingEmailOrPasswordIsNotCounted(t *testing.T) {
	f := newLoginDelayFixture(t)
	for range 10 {
		req := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(`{"email":"victim@example.com","password":""}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		f.h.Login(w, req)
		require.Equal(t, http.StatusUnauthorized, w.Code)
	}
	assert.Equal(t, http.StatusUnauthorized, f.login("victim@example.com").Code, "no password was ever guessed")
}

func TestLoginDelay_ParallelGuessesAreCountedBeforeTheyAreEvaluated(t *testing.T) {
	f := newLoginDelayFixture(t)
	var wg sync.WaitGroup
	var blocked atomic.Int64
	for range 200 {
		wg.Go(func() {
			if f.login("victim@example.com").Code == http.StatusTooManyRequests {
				blocked.Add(1)
			}
		})
	}
	wg.Wait()
	assert.EqualValues(t, 3, f.calls.Load(), "a burst of parallel guesses gets exactly the free attempts")
	assert.EqualValues(t, 197, blocked.Load())
}

func TestLoginDelay_ManyAccountsInParallel(t *testing.T) {
	f := newLoginDelayFixture(t)
	var wg sync.WaitGroup
	for g := range 50 {
		wg.Go(func() {
			for i := range 20 {
				f.login(fmt.Sprintf("user%d@example.com", (g+i)%10))
			}
		})
	}
	wg.Wait()
	assert.EqualValues(t, 10*3, f.calls.Load(), "each of the ten accounts gets its three free attempts")
	assert.Equal(t, 10, f.h.loginDelay.accountCount())
}

func TestLoginDelay_StateIsBoundedAndFailsClosedWhenFull(t *testing.T) {
	f := newLoginDelayFixture(t)
	f.h.loginDelay.store.max = 20

	for i := range 500 {
		f.login(fmt.Sprintf("flood%d@example.com", i))
	}
	assert.LessOrEqual(t, f.h.loginDelay.accountCount(), 20)

	// New accounts now share the overflow counter, which the flood has
	// already pushed into a wait.
	assert.Equal(t, http.StatusTooManyRequests, f.login("late-arrival@example.com").Code)

	// An account that already has state keeps its own counter.
	f2 := newLoginDelayFixture(t)
	f2.h.loginDelay.store.max = 20
	f2.login("victim@example.com")
	for i := range 500 {
		f2.login(fmt.Sprintf("flood%d@example.com", i))
	}
	assert.Equal(t, http.StatusUnauthorized, f2.login("victim@example.com").Code, "its second failure is still evaluated")
}

func TestRouter_LoginDelayAppliesAcrossAddressesAndPrefixes(t *testing.T) {
	var calls atomic.Int64
	router := NewRouter(RouterConfig{
		Usecases: &mockUsecases{loginFn: func(context.Context, string, string) (*usecase.AuthResponse, error) {
			calls.Add(1)
			return nil, errors.New("invalid email or password")
		}},
		JWTAuth: testJWTAuth,
	})
	send := func(remote string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(`{"email":"victim@example.com","password":"guess"}`))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = remote
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
	require.Equal(t, http.StatusUnauthorized, send("192.0.2.1:1").Code)
	require.Equal(t, http.StatusUnauthorized, send("198.51.100.1:1").Code)
	require.Equal(t, http.StatusUnauthorized, send("[2001:db8:a::1]:1").Code)

	w := send("203.0.113.9:1")
	require.Equal(t, http.StatusTooManyRequests, w.Code, "a fourth address cannot add a guess against the same account")
	assert.Contains(t, w.Body.String(), "too_many_attempts")
	assert.NotEmpty(t, w.Header().Get("Retry-After"))
	assert.EqualValues(t, 3, calls.Load())
}
