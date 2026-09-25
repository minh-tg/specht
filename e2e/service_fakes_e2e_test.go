//go:build e2e

package e2e

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// watcherStatus is the watcher health contract (BP-47).
type watcherStatus struct {
	LastSuccessfulPollAt string `json:"last_successful_poll_at"`
	LastPollAttemptAt    string `json:"last_poll_attempt_at"`
	LastError            string `json:"last_error"`
	ConsecutiveFailures  int32  `json:"consecutive_failures"`
	Healthy              bool   `json:"healthy"`
	Stale                bool   `json:"stale"`
}

// fetchWatcherStatus avoids require inside Eventually conditions (they run
// on testify's goroutine, where FailNow is illegal).
func fetchWatcherStatus() (watcherStatus, bool) {
	req, err := http.NewRequest(http.MethodGet, baseURL+"/api/v1/watcher/status", nil)
	if err != nil {
		return watcherStatus{}, false
	}
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return watcherStatus{}, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return watcherStatus{}, false
	}
	var s watcherStatus
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		return watcherStatus{}, false
	}
	return s, true
}

// TestE2E_ServiceWiring proves each harness fake is live behind the real
// server: the SSO login redirects to the loopback IdP, the watcher daemon
// polls the fake OSV with real inventory and stays healthy, and finding
// events reach the signed webhook tracker sink.
func TestE2E_ServiceWiring(t *testing.T) {
	t.Run("sso login redirects to the loopback identity provider", func(t *testing.T) {
		noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}}
		req, err := http.NewRequest(http.MethodGet, baseURL+"/api/v1/auth/sso/login", nil)
		require.NoError(t, err)
		resp, err := noRedirect.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusFound, resp.StatusCode)
		loc := resp.Header.Get("Location")
		require.True(t, stringsKeep(loc, fakes.idp.Issuer()+"/oauth/authorize"),
			"redirect targets the configured IdP: %s", loc)
		require.Contains(t, loc, "client_id="+e2eIdPClientID)
		require.Contains(t, loc, "state=")
	})

	t.Run("watcher polls the fake OSV with real inventory", func(t *testing.T) {
		// A package-producing trivy scan seeds inventory the daemon must
		// query on its 1s poll cycle.
		slug := newProject(t, "fakes-watcher")
		ingestRaw(t, slug, "trivy", "trivy-packages-scan.json", nil)

		// Manual loop so a timeout can dump the server log: the poll
		// loop's health is only explainable from the daemon's own words.
		deadline := time.Now().Add(25 * time.Second)
		for time.Now().Before(deadline) {
			s, ok := fetchWatcherStatus()
			t.Logf("probe: osv_calls=%d status_ok=%v attempt=%q success=%q last_error=%q failures=%d",
				fakes.osv.callCount(), ok, s.LastPollAttemptAt, s.LastSuccessfulPollAt,
				s.LastError, s.ConsecutiveFailures)
			if fakes.osv.callCount() > 0 {
				break
			}
			time.Sleep(2 * time.Second)
		}
		if fakes.osv.callCount() == 0 {
			t.Logf("fake OSV endpoint: %s", fakes.osv.URL())
			t.Logf("server log tail:\n%s", serverLogTail())
			require.FailNow(t, "the poll cycle reaches the configured OSV endpoint")
		}

		var status watcherStatus
		require.Eventually(t, func() bool {
			s, ok := fetchWatcherStatus()
			if ok {
				status = s
			}
			return ok && status.LastPollAttemptAt != "" && status.LastSuccessfulPollAt != ""
		}, 25*time.Second, 250*time.Millisecond,
			"status records a successful poll")
		require.Empty(t, status.LastError, "polls against the fake succeed")
		require.Zero(t, status.ConsecutiveFailures)
		require.True(t, status.Healthy, "a fresh successful poll is healthy")
		require.False(t, status.Stale)
	})

	t.Run("finding events reach the signed webhook tracker", func(t *testing.T) {
		before := fakes.trackerSink.count()
		slug := newProject(t, "fakes-tracker")
		ingestRaw(t, slug, "trivy", "trivy-alpine-scan.json", nil)

		require.Eventually(t, func() bool {
			return fakes.trackerSink.count() > before
		}, 25*time.Second, 250*time.Millisecond,
			"finding-created events dispatch to the webhook tracker")

		var hit *capturedRequest
		for _, r := range fakes.trackerSink.snapshot() {
			if r.Header.Get("X-Tracker-Event") != "" {
				rr := r
				hit = &rr
			}
		}
		require.NotNil(t, hit, "a tracker delivery carries the event header")
		require.Equal(t, "created", hit.Header.Get("X-Tracker-Event"))
		require.Equal(t, "/tracker", hit.Path)

		sig := hit.Header.Get("X-Specht-Signature")
		require.NotEmpty(t, sig, "deliveries are signed")
		mac := hmac.New(sha256.New, []byte(e2eWebhookSecret))
		_, _ = mac.Write(hit.Body)
		require.Equal(t, "sha256="+hex.EncodeToString(mac.Sum(nil)), sig,
			"the signature verifies with the configured secret")
	})
}
