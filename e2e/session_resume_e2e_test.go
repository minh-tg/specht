//go:build e2e

package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const resumePath = "/api/v1/auth/resume"

// resumeCookieFrom reads the resume cookie a sign-in response set.
func resumeCookieFrom(t *testing.T, resp *http.Response) *http.Cookie {
	t.Helper()
	for _, c := range resp.Cookies() {
		if c.Name == "specht_resume" {
			return c
		}
	}
	require.Fail(t, "the response set no resume cookie")
	return nil
}

// signInWithCookie logs in and returns the session and the cookie the browser keeps.
func signInWithCookie(t *testing.T, email, password string) (authResponse, *http.Cookie) {
	t.Helper()
	body, err := json.Marshal(map[string]string{"email": email, "password": password})
	require.NoError(t, err)
	var resp *http.Response
	// Tests share one client address, and login has its own small rate bucket.
	for range 60 {
		resp, err = http.Post(baseURL+"/api/v1/auth/login", "application/json", strings.NewReader(string(body)))
		require.NoError(t, err)
		if resp.StatusCode != http.StatusTooManyRequests {
			break
		}
		_ = resp.Body.Close()
		time.Sleep(500 * time.Millisecond)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
	var session authResponse
	require.NoError(t, json.Unmarshal(raw, &session))
	return session, resumeCookieFrom(t, resp)
}

// resume calls the endpoint a new tab calls, waiting out the rate limit that the
// tests' one shared client address runs into.
func resume(t *testing.T, cookie *http.Cookie, withHeader bool) (int, authResponse) {
	t.Helper()
	for range 60 {
		req, err := http.NewRequest(http.MethodPost, baseURL+resumePath, nil)
		require.NoError(t, err)
		if withHeader {
			req.Header.Set("X-Specht-Resume", "1")
		}
		if cookie != nil {
			req.AddCookie(&http.Cookie{Name: cookie.Name, Value: cookie.Value})
		}
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		raw, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		require.NoError(t, err)
		if resp.StatusCode == http.StatusTooManyRequests {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		var session authResponse
		if resp.StatusCode == http.StatusOK {
			require.NoError(t, json.Unmarshal(raw, &session))
		}
		require.Equal(t, "no-store", resp.Header.Get("Cache-Control"))
		return resp.StatusCode, session
	}
	require.Fail(t, "still rate limited")
	return 0, authResponse{}
}

// refreshOK rotates a token and expects it to work, waiting out the rate limit.
func refreshOK(t *testing.T, token string) {
	t.Helper()
	for range 60 {
		status, raw := doJSON(t, http.MethodPost, "/api/v1/auth/refresh", "", map[string]string{"refresh_token": token})
		if status == http.StatusTooManyRequests {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		require.Equal(t, http.StatusOK, status, string(raw))
		return
	}
	require.Fail(t, "still rate limited")
}

// TestE2E_SessionResume pins the new-tab session: a CI link opened in a new tab
// continues the browser's sign-in, and everything that ends a sign-in ends this too.
func TestE2E_SessionResume(t *testing.T) {
	// These calls spend the shared auth rate limit of the tests' one client address.
	// Let it refill so the next test does not pay for them.
	t.Cleanup(func() { time.Sleep(3 * time.Second) })

	t.Run("the cookie is out of reach of scripts and other sites", func(t *testing.T) {
		_, cookie := signInWithCookie(t, adminEmail, adminPass)
		require.True(t, cookie.HttpOnly)
		require.Equal(t, http.SameSiteStrictMode, cookie.SameSite)
		require.Equal(t, resumePath, cookie.Path)
		require.Zero(t, cookie.MaxAge, "a session cookie: closing the browser ends it")
		require.True(t, cookie.Expires.IsZero())
	})

	t.Run("a new tab gets its own working session", func(t *testing.T) {
		first, cookie := signInWithCookie(t, adminEmail, adminPass)
		status, tab := resume(t, cookie, true)
		require.Equal(t, http.StatusOK, status)
		require.NotEmpty(t, tab.Token)
		require.NotEqual(t, first.RefreshToken, tab.RefreshToken, "each tab rotates its own token")

		me := request[authResponse](t, http.MethodGet, "/api/v1/me", tab.Token, nil, http.StatusOK)
		require.Equal(t, adminEmail, me.Email)

		refreshOK(t, tab.RefreshToken)
		refreshOK(t, first.RefreshToken)
	})

	t.Run("tabs opened at once all resume, and none reads as a replay", func(t *testing.T) {
		first, cookie := signInWithCookie(t, adminEmail, adminPass)
		var wg sync.WaitGroup
		statuses := make([]int, 8)
		for i := range statuses {
			wg.Add(1)
			go func() {
				defer wg.Done()
				statuses[i], _ = resume(t, cookie, true)
			}()
		}
		wg.Wait()
		for _, status := range statuses {
			require.Equal(t, http.StatusOK, status)
		}
		refreshOK(t, first.RefreshToken)
	})

	t.Run("a request without the header is refused", func(t *testing.T) {
		_, cookie := signInWithCookie(t, adminEmail, adminPass)
		status, _ := resume(t, cookie, false)
		require.Equal(t, http.StatusForbidden, status)
	})

	t.Run("no cookie and a bad cookie are nothing to resume", func(t *testing.T) {
		status, _ := resume(t, nil, true)
		require.Equal(t, http.StatusNoContent, status)
		status, _ = resume(t, &http.Cookie{Name: "specht_resume", Value: "not-a-token"}, true)
		require.Equal(t, http.StatusNoContent, status)
	})

	t.Run("signing out ends the cookie and every tab of this sign-in", func(t *testing.T) {
		first, cookie := signInWithCookie(t, adminEmail, adminPass)
		_, tab := resume(t, cookie, true)
		other, otherCookie := signInWithCookie(t, adminEmail, adminPass)

		eventually(t, 30*time.Second, "sign out", func() bool {
			status, _ := doJSON(t, http.MethodPost, "/api/v1/auth/logout", first.Token,
				map[string]string{"refresh_token": first.RefreshToken})
			return status == http.StatusNoContent
		})

		status, _ := resume(t, cookie, true)
		require.Equal(t, http.StatusNoContent, status, "the cookie ended with the sign-in")
		eventually(t, 30*time.Second, "the resumed tab ended with the sign-in", func() bool {
			status, _ := doJSON(t, http.MethodPost, "/api/v1/auth/refresh", "",
				map[string]string{"refresh_token": tab.RefreshToken})
			return status == http.StatusUnauthorized
		})

		status, _ = resume(t, otherCookie, true)
		require.Equal(t, http.StatusOK, status, "another sign-in is a separate chain")
		refreshOK(t, other.RefreshToken)
	})

	t.Run("a deactivated account cannot resume", func(t *testing.T) {
		const email = "e2e-viewer@example.com"
		_, cookie := signInWithCookie(t, email, adminPass)
		tabStatus, tab := resume(t, cookie, true)
		require.Equal(t, http.StatusOK, tabStatus)
		me := request[userProfile](t, http.MethodGet, "/api/v1/me", tab.Token, nil, http.StatusOK)
		base := "/api/v1/users/" + me.ID
		t.Cleanup(func() { doJSON(t, http.MethodPost, base+"/reactivate", adminToken, nil) })

		status, raw := doJSON(t, http.MethodPost, base+"/deactivate", adminToken, nil)
		require.Equal(t, http.StatusOK, status, string(raw))
		status, _ = resume(t, cookie, true)
		require.Equal(t, http.StatusNoContent, status)
	})

	t.Run("a password change ends the old cookie and sets a new one", func(t *testing.T) {
		const (
			email = "e2e-viewer@example.com"
			next  = "another-Long-passw0rd-77"
		)
		session, cookie := signInWithCookie(t, email, adminPass)
		t.Cleanup(func() {
			again, _ := signInWithCookie(t, email, next)
			doJSON(t, http.MethodPut, "/api/v1/me/password", again.Token,
				map[string]string{"current_password": next, "new_password": adminPass})
		})

		body, err := json.Marshal(map[string]string{"current_password": adminPass, "new_password": next})
		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodPut, baseURL+"/api/v1/me/password", strings.NewReader(string(body)))
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+session.Token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		status, _ := resume(t, cookie, true)
		require.Equal(t, http.StatusNoContent, status, "the old cookie died with the password")
		status, _ = resume(t, resumeCookieFrom(t, resp), true)
		require.Equal(t, http.StatusOK, status, "this browser stays signed in")
	})

	t.Run("an account with no password resumes too", func(t *testing.T) {
		fakes.idp.setEmail("e2e-resume-sso@example.com")
		status, location, cookies := ssoExchange(t, "")
		code := ssoCodeFrom(t, status, location)
		st, body, setCookies := exchangeCode(t, code, cookies...)
		require.Equal(t, http.StatusOK, st, string(body))

		var cookie *http.Cookie
		for _, c := range setCookies {
			if c.Name == "specht_resume" {
				cookie = c
			}
		}
		require.NotNil(t, cookie, "an SSO sign-in sets the resume cookie")
		st, _ = resume(t, cookie, true)
		require.Equal(t, http.StatusOK, st)
	})

	t.Run("a resume issues a fresh cookie, so an active browser keeps its sign-in", func(t *testing.T) {
		_, cookie := signInWithCookie(t, adminEmail, adminPass)
		req, err := http.NewRequest(http.MethodPost, baseURL+resumePath, nil)
		require.NoError(t, err)
		req.Header.Set("X-Specht-Resume", "1")
		req.AddCookie(&http.Cookie{Name: cookie.Name, Value: cookie.Value})
		var resp *http.Response
		for range 60 {
			resp, err = http.DefaultClient.Do(req)
			require.NoError(t, err)
			if resp.StatusCode != http.StatusTooManyRequests {
				break
			}
			_ = resp.Body.Close()
			time.Sleep(500 * time.Millisecond)
		}
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		next := resumeCookieFrom(t, resp)
		require.NotEqual(t, cookie.Value, next.Value)
		status, _ := resume(t, next, true)
		require.Equal(t, http.StatusOK, status)
	})
}
