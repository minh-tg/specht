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

// setLoginDelayCap shrinks the account store so a test can fill it without
// 100,000 requests. TestNewLoginDelay_UsesTheSharedCap pins the real value.
func setLoginDelayCap(d *loginDelay, n int) { d.max = n }

func TestNewLoginDelay_UsesTheSharedCap(t *testing.T) {
	assert.Equal(t, maxLiveBuckets, newLoginDelay().max)
}

func TestLoginDelay_FullStoreOfSingleFailuresStillServesFreshAccounts(t *testing.T) {
	f := newLoginDelayFixture(t)
	setLoginDelayCap(f.h.loginDelay, 20)

	for i := range 500 {
		f.login(fmt.Sprintf("flood%d@example.com", i))
	}
	assert.LessOrEqual(t, f.h.loginDelay.accountCount(), 20)

	// A fresh account has its own counter: its first three guesses are
	// evaluated, and the right password signs in.
	for i := range 3 {
		require.Equal(t, http.StatusUnauthorized, f.login("late-arrival@example.com").Code, "guess %d is evaluated", i+1)
	}
	f.success.Store(true)
	f.advance(time.Minute)
	assert.Equal(t, http.StatusOK, f.login("late-arrival@example.com").Code)
}

func TestLoginDelay_FloodCannotRaiseAWaitOnAFreshAccount(t *testing.T) {
	f := newLoginDelayFixture(t)
	setLoginDelayCap(f.h.loginDelay, 20)
	for i := range 2000 {
		f.login(fmt.Sprintf("flood%d@example.com", i%700))
		f.advance(10 * time.Millisecond)
	}
	f.success.Store(true)
	for i := range 40 {
		email := fmt.Sprintf("fresh%d@example.com", i)
		assert.Equal(t, http.StatusOK, f.login(email).Code, "%s signs in with the right password", email)
	}
}

func TestLoginDelay_AccountThatHasStateKeepsItsCounterUnderFlood(t *testing.T) {
	f := newLoginDelayFixture(t)
	setLoginDelayCap(f.h.loginDelay, 20)
	f.login("victim@example.com")
	f.login("victim@example.com")
	f.login("victim@example.com")
	for i := range 500 {
		f.login(fmt.Sprintf("flood%d@example.com", i))
	}
	assert.Equal(t, http.StatusTooManyRequests, f.login("victim@example.com").Code,
		"the victim's wait survives a flood of single failures")
}

func TestLoginDelay_BlockedEntriesAreNeverEvictedForANewcomer(t *testing.T) {
	f := newLoginDelayFixture(t)
	setLoginDelayCap(f.h.loginDelay, 20)
	for i := range 10 {
		for range 3 {
			f.login(fmt.Sprintf("blocked%d@example.com", i))
		}
	}
	for i := range 10 {
		f.login(fmt.Sprintf("single%d@example.com", i))
	}
	require.Equal(t, 20, f.h.loginDelay.accountCount())

	for i := range 500 {
		f.login(fmt.Sprintf("newcomer%d@example.com", i))
	}
	for i := range 10 {
		assert.Equal(t, http.StatusTooManyRequests, f.login(fmt.Sprintf("blocked%d@example.com", i)).Code,
			"blocked%d keeps its wait", i)
	}
}

func TestLoginDelay_WhenEveryEntryIsBlockedANewEmailIsNotTracked(t *testing.T) {
	f := newLoginDelayFixture(t)
	setLoginDelayCap(f.h.loginDelay, 20)
	for i := range 20 {
		for range 3 {
			f.login(fmt.Sprintf("blocked%d@example.com", i))
		}
	}
	require.Equal(t, 20, f.h.loginDelay.accountCount())

	// The newcomer is neither refused nor remembered: the per-IP login
	// bucket is the only limit left on it.
	for range 10 {
		require.Equal(t, http.StatusUnauthorized, f.login("newcomer@example.com").Code)
	}
	assert.Equal(t, 20, f.h.loginDelay.accountCount())
	f.success.Store(true)
	assert.Equal(t, http.StatusOK, f.login("newcomer@example.com").Code)
	assert.Equal(t, 20, f.h.loginDelay.accountCount())
}

func TestLoginDelay_ExpiredEntriesAreSweptWhenTheStoreIsFull(t *testing.T) {
	f := newLoginDelayFixture(t)
	setLoginDelayCap(f.h.loginDelay, 20)
	for i := range 20 {
		for range 3 {
			f.login(fmt.Sprintf("old%d@example.com", i))
		}
	}
	f.advance(loginDelayDecay + time.Second)
	f.success.Store(true)
	assert.Equal(t, http.StatusOK, f.login("newcomer@example.com").Code)
	f.success.Store(false)
	f.login("newcomer@example.com")
	f.login("newcomer@example.com")
	f.login("newcomer@example.com")
	assert.Equal(t, http.StatusTooManyRequests, f.login("newcomer@example.com").Code,
		"the newcomer got a slot once the old waits had expired, so its own counter works")
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
