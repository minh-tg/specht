//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/repo"
)

// Races between the credential lifecycle events (an SSO link, a deactivation)
// and a request that passed authentication or the password check before the
// event committed. Each test asserts that nothing the request produced outlives
// the event.

func racePool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool
}

type raceLoginResult struct {
	status int
	resp   authResponse
}

func raceLogin(email, pass string) raceLoginResult {
	status, body, err := postJSON(baseURL+"/api/v1/auth/login", "", map[string]string{"email": email, "password": pass})
	if err != nil {
		return raceLoginResult{status: -1}
	}
	var out authResponse
	_ = json.Unmarshal(body, &out)
	return raceLoginResult{status: status, resp: out}
}

// A squatter's password Login that verifies the old password while the owner's
// SSO link commits must not come away with a working session.
func TestLoginStraddlingSSOLinkKeepsNoSession(t *testing.T) {
	ctx := context.Background()
	pool := racePool(t)
	stores := repo.NewPortStores(pool)

	// Measure one login to place the link inside the password verify.
	time.Sleep(2 * time.Second)
	probeEmail := "race-probe-" + randomHex(4) + "@example.com"
	probePass := "probe-password-" + randomHex(6)
	request[authResponse](t, http.MethodPost, "/api/v1/auth/register", "",
		map[string]string{"email": probeEmail, "password": probePass}, http.StatusCreated)
	start := time.Now()
	require.Equal(t, http.StatusOK, raceLogin(probeEmail, probePass).status)
	loginDur := time.Since(start)
	t.Logf("one login takes %v", loginDur)

	const rounds = 3
	survived := 0
	for i := 0; i < rounds; i++ {
		time.Sleep(600 * time.Millisecond) // public routes share a 10 rps per-IP bucket
		email := "race-squat-" + randomHex(4) + "@example.com"
		pass := "squatter-password-" + randomHex(6)
		sq := request[authResponse](t, http.MethodPost, "/api/v1/auth/register", "",
			map[string]string{"email": email, "password": pass}, http.StatusCreated)

		done := make(chan raceLoginResult, 1)
		go func() { done <- raceLogin(email, pass) }()
		// Land the link at 20%, 50% and 80% of the login's duration.
		time.Sleep(time.Duration(int64(loginDur) * int64(2+3*i) / 10))
		_, _, err := stores.Identities.LinkRevokingKeys(ctx, sq.UserID, "https://idp.example.com", "sub-"+randomHex(6), true)
		require.NoError(t, err)
		res := <-done
		if res.status != http.StatusOK {
			continue
		}
		meStatus, _ := doJSON(t, http.MethodGet, "/api/v1/me", res.resp.Token, nil)
		refStatus, refRaw := doJSON(t, http.MethodPost, "/api/v1/auth/refresh", "",
			map[string]string{"refresh_token": res.resp.RefreshToken})
		t.Logf("round %d: login 200 after link; /me=%d refresh=%d", i, meStatus, refStatus)
		if meStatus == http.StatusOK || refStatus == http.StatusOK {
			survived++
			if refStatus == http.StatusOK {
				var again authResponse
				require.NoError(t, json.Unmarshal(refRaw, &again))
				s, _ := doJSON(t, http.MethodGet, "/api/v1/me", again.Token, nil)
				t.Logf("round %d: refreshed access token on the linked account answers /me=%d", i, s)
			}
		}
	}
	require.Zero(t, survived, "squatter sessions that survived the SSO link")
}

// Same window against deactivation: Login reads DisabledAt before the verify.
func TestLoginStraddlingDeactivationGetsNoToken(t *testing.T) {
	ctx := context.Background()
	pool := racePool(t)
	stores := repo.NewPortStores(pool)

	time.Sleep(2 * time.Second)
	probeEmail := "race-probe-" + randomHex(4) + "@example.com"
	probePass := "probe-password-" + randomHex(6)
	request[authResponse](t, http.MethodPost, "/api/v1/auth/register", "",
		map[string]string{"email": probeEmail, "password": probePass}, http.StatusCreated)
	start := time.Now()
	require.Equal(t, http.StatusOK, raceLogin(probeEmail, probePass).status)
	loginDur := time.Since(start)

	const rounds = 3
	survived := 0
	for i := 0; i < rounds; i++ {
		time.Sleep(600 * time.Millisecond)
		email := "race-deact-" + randomHex(4) + "@example.com"
		pass := "deact-password-" + randomHex(6)
		u := request[authResponse](t, http.MethodPost, "/api/v1/auth/register", "",
			map[string]string{"email": email, "password": pass}, http.StatusCreated)
		done := make(chan raceLoginResult, 1)
		go func() { done <- raceLogin(email, pass) }()
		time.Sleep(time.Duration(int64(loginDur) * int64(2+3*i) / 10))
		_, err := stores.Users.SetDisabled(ctx, u.UserID, true)
		require.NoError(t, err)
		res := <-done
		if res.status != http.StatusOK {
			continue
		}
		meStatus, _ := doJSON(t, http.MethodGet, "/api/v1/me", res.resp.Token, nil)
		t.Logf("round %d: login 200 after deactivation; /me=%d", i, meStatus)
		if meStatus == http.StatusOK {
			survived++
		}
	}
	require.Zero(t, survived, "access tokens minted for a deactivated account")
}

// A squatter's key creation request that passed authentication before the
// owner's SSO link commits must not leave a live key on the linked account.
func TestKeyCreateStraddlingSSOLinkLeavesNoKey(t *testing.T) {
	ctx := context.Background()
	pool := racePool(t)
	stores := repo.NewPortStores(pool)

	const rounds = 3
	survivors := 0
	for i := 0; i < rounds; i++ {
		time.Sleep(600 * time.Millisecond)
		slug := newProject(t, "race-link-keys")
		email := "race-keysq-" + randomHex(4) + "@example.com"
		pass := "squatter-password-" + randomHex(6)
		sq := request[authResponse](t, http.MethodPost, "/api/v1/auth/register", "",
			map[string]string{"email": email, "password": pass}, http.StatusCreated)
		request[memberResponse](t, http.MethodPost, "/api/v1/projects/"+slug+"/members", adminToken,
			map[string]string{"user_id": sq.UserID, "role": "admin"}, http.StatusCreated)
		token := login(t, email, pass)

		var wg sync.WaitGroup
		for j := 0; j < 16; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _, _ = postJSON(baseURL+"/api/v1/auth/apikeys", token,
					map[string]string{"project": slug, "name": "sq-" + randomHex(3)})
			}()
		}
		time.Sleep(time.Duration(i) * time.Millisecond)
		_, _, err := stores.Identities.LinkRevokingKeys(ctx, sq.UserID, "https://idp.example.com", "sub-"+randomHex(6), true)
		require.NoError(t, err)
		wg.Wait()
		var live int
		require.NoError(t, pool.QueryRow(ctx,
			"SELECT count(*) FROM api_keys WHERE created_by = $1 AND revoked_at IS NULL", sq.UserID).Scan(&live))
		if live > 0 {
			t.Logf("round %d: %d squatter keys survived the link", i, live)
		}
		survivors += live
	}
	require.Zero(t, survivors, "squatter keys alive on the linked account")
}
