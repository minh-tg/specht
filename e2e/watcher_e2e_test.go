//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// The CVE watcher daemon over the fake OSV feed, its status surfaces, the
// backfill CLI, and its notifications.

// armLodashAdvisory advertises an OSV record matching the lodash inventory
// of trivy-npm-packages-scan.json: fixed in 4.18.0, CVSS 3.1 high.
func armLodashAdvisory() string {
	const id = "OSV-2026-777"
	// The daemon polls every second and advances a project's watermark on EVERY
	// successful poll, including a poll of a project that has no inventory yet
	// (between newProject and the scan being ingested). Warm polls then skip
	// advisories published before that watermark, by design: the watcher reports
	// NEW advisories, scans cover the old ones. A fixed past date therefore made
	// this fixture depend on winning a race against the first poll, which a slow
	// CI runner loses about half the time. Dating the advisory after any
	// watermark the daemon can have recorded makes it eligible in both orders.
	published := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	fakes.osv.arm("lodash", map[string]any{
		"id":        id,
		"aliases":   []string{"CVE-2026-777"},
		"summary":   "lodash prototype pollution before 4.18.0",
		"details":   "A prototype pollution flaw in lodash versions before 4.18.0 allows attackers to inject properties.",
		"published": published,
		"modified":  published,
		"severity": []map[string]string{{
			"type":  "CVSS_V3",
			"score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		}},
		"affected": []map[string]any{{
			"ecosystem": "npm",
			"package":   map[string]string{"name": "lodash"},
			"ranges": []map[string]any{{
				"type": "ECOSYSTEM",
				"events": []map[string]string{
					{"introduced": "0"},
					{"fixed": "4.18.0"},
				},
			}},
			"versions": []string{"4.17.19"},
		}},
		"references": []map[string]string{{"url": "https://example.test/CVE-2026-777"}},
	})
	return id
}

// fetchFindings avoids require inside manual wait loops.
func fetchFindings(slug string) ([]scanFinding, bool) {
	req, err := http.NewRequest(http.MethodGet,
		baseURL+"/api/v1/projects/"+slug+"/findings?limit=50", nil)
	if err != nil {
		return nil, false
	}
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false
	}
	var out []scanFinding
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, false
	}
	return out, true
}

// setWatcherEnabled flips the per-project watcher switch directly: the
// product has no API for it, and the backfill subtests need the live daemon
// out of the way (a precondition, like the retention backdating).
func setWatcherEnabled(t *testing.T, slug string, enabled bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	defer conn.Close(ctx)
	tag, err := conn.Exec(ctx,
		"UPDATE projects SET cve_watcher_enabled = $1 WHERE slug = $2", enabled, slug)
	require.NoError(t, err)
	require.Equal(t, int64(1), tag.RowsAffected())
}

// TestE2E_WatcherDaemonLifecycle closes the watcher arc: an armed advisory on
// the injected feed becomes a gated cve_watcher finding exactly once (with
// advisory evidence and a notification), status reports healthy over API
// and CLI, and the backfill CLI honors --dry-run before writing.
func TestE2E_WatcherDaemonLifecycle(t *testing.T) {
	// Every project this test creates, retired together at the end. The
	// advisory stays armed and the projects stay enabled while the subtests
	// run: disarming under a live poll is what wrote a spurious 404 into the
	// shared watcher health row and failed the status subtest.
	var created []string
	t.Cleanup(func() {
		for _, slug := range created {
			setWatcherEnabled(t, slug, false)
		}
		// One poll interval plus slack: the daemon prunes the disabled
		// projects and any poll already in flight finishes while the feed
		// still serves the advisory.
		time.Sleep(1500 * time.Millisecond)
		fakes.osv.disarm()
	})

	t.Run("armed advisory becomes a gated watcher finding exactly once", func(t *testing.T) {
		slug := newProject(t, "watcher-advisory")
		created = append(created, slug)
		// Let the daemon poll the still-empty project first, so its watermark is
		// already set when the scan and the advisory arrive. That is the realistic
		// order (a new advisory appears after the project was first polled) and it
		// makes this subtest deterministic instead of racing the first poll.
		time.Sleep(2500 * time.Millisecond)
		ingestRaw(t, slug, "trivy", "trivy-npm-packages-scan.json", nil)
		notifyBefore := fakes.notifySink.count()
		armLodashAdvisory()

		var found []scanFinding
		deadline := time.Now().Add(25 * time.Second)
		for time.Now().Before(deadline) {
			if fs, ok := fetchFindings(slug); ok && len(fs) > 0 {
				found = fs
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
		if len(found) != 1 {
			t.Logf("server log tail:\n%s", serverLogTail())
		}
		require.Len(t, found, 1, "the armed advisory creates one watcher finding")
		f := found[0]
		require.Equal(t, "cve_watcher", f.FindingKind)
		require.Contains(t, f.CurrentTitle, "lodash", "the finding names the advisory")
		require.Equal(t, "critical", f.CurrentSeverity,
			"CVSS 3.1 9.8 (C:H/I:H/A:H) maps to critical")
		require.Equal(t, "open", f.State)

		// require_triage (the column default): an UNTRIAGED watcher
		// finding is dropped from the gate — analysts look before it
		// counts. The default floor would otherwise see a critical.
		gate := getGate(t, slug, "")
		require.False(t, gate.ThresholdBreached,
			"an untriaged watcher finding does not gate under require_triage")

		// Triaging it to exploitable makes it count: the gate flips.
		request[triageOutput](t, http.MethodPatch, "/api/v1/findings/"+f.ID, adminToken,
			map[string]any{"analysis_state": "exploitable", "reason": "confirmed by the E2E fixture"},
			http.StatusOK)
		require.True(t, getGate(t, slug, "").ThresholdBreached,
			"a triaged watcher finding blocks the gate")

		// Triaging it away opens the gate again.
		request[triageOutput](t, http.MethodPatch, "/api/v1/findings/"+f.ID, adminToken,
			map[string]any{"analysis_state": "false_positive", "reason": "E2E fixture advisory"},
			http.StatusOK)
		require.False(t, getGate(t, slug, "").ThresholdBreached,
			"triaging the watcher finding as a false positive opens the gate")

		// The raw advisory lands as evidence on the finding.
		evidence := request[[]evidenceResponse](t, http.MethodGet,
			"/api/v1/findings/"+f.ID+"/evidence", adminToken, nil, http.StatusOK)
		require.NotEmpty(t, evidence, "the advisory record persists as evidence")

		// The creation fans out to the generic webhook sink.
		requireEventually(t, 15*time.Second, func() bool {
			return fakes.notifySink.count() > notifyBefore
		}, "the notifier receives the created finding")

		// Watermark + gap-fill idempotency: further 1s polls never
		// duplicate or reopen the finding.
		time.Sleep(3 * time.Second)
		again, ok := fetchFindings(slug)
		require.True(t, ok)
		require.Len(t, again, 1, "re-polls do not duplicate the finding")
	})

	t.Run("watcher status reports healthy over API and CLI", func(t *testing.T) {
		// Wait for a fully healthy row rather than a recorded attempt: the
		// row is shared by every project, so a transient failure clears only
		// on the next successful round.
		var status watcherStatus
		requireEventually(t, 20*time.Second, func() bool {
			s, ok := fetchWatcherStatus()
			if !ok {
				return false
			}
			status = s
			return status.LastSuccessfulPollAt != "" && status.LastPollAttemptAt != "" &&
				status.LastError == "" && status.ConsecutiveFailures == 0 &&
				status.Healthy && !status.Stale
		}, "status reports a completed successful poll")
		require.Empty(t, status.LastError)
		require.Zero(t, status.ConsecutiveFailures)
		require.True(t, status.Healthy)
		require.False(t, status.Stale)

		stdout, stderr, exit := runBin(t, cliBin,
			[]string{"API_URL=" + baseURL, "API_KEY=" + adminToken},
			"watcher", "status")
		require.Equal(t, 0, exit, "stderr: %s", stderr)
		require.Contains(t, stdout, "Last Successful Poll:")
		require.Contains(t, stdout, "Status:                healthy")
	})

	t.Run("backfill dry-run persists nothing and the real run writes", func(t *testing.T) {
		slug := newProject(t, "watcher-backfill")
		created = append(created, slug)
		// Disable BEFORE ingesting or arming: the live daemon polls every
		// second, and a project that exists, has inventory, and sees the
		// armed advisory inside the create to disable window would get its
		// finding created by the daemon instead of the CLI.
		setWatcherEnabled(t, slug, false)
		ingestRaw(t, slug, "trivy", "trivy-npm-packages-scan.json", nil)
		armLodashAdvisory()

		// The disabled project stays out of the live schedule.
		time.Sleep(3 * time.Second)
		pre, ok := fetchFindings(slug)
		require.True(t, ok)
		require.Empty(t, pre, "a disabled project is pruned from the live schedule")

		backfillEnv := []string{
			"DATABASE_URL=" + dsn,
			"WATCHER_OSV_ENDPOINT=" + fakes.osv.URL(),
			"WATCHER_OSV_VULN_ENDPOINT=" + fakes.osv.VulnURL(),
		}

		stdout, stderr, exit := runBin(t, cliBin, backfillEnv,
			"watcher", "backfill", "--dry-run")
		require.Equal(t, 0, exit, "stderr: %s", stderr)
		require.Contains(t, stdout, "dry-run: nothing was written")
		mid, ok := fetchFindings(slug)
		require.True(t, ok)
		require.Empty(t, mid, "--dry-run writes nothing")

		stdout, stderr, exit = runBin(t, cliBin, backfillEnv,
			"watcher", "backfill")
		require.Equal(t, 0, exit, "stderr: %s", stderr)
		require.Contains(t, stdout, "created=1", "the backfill reports the new finding: %s", stdout)

		var after []scanFinding
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if fs, ok := fetchFindings(slug); ok && len(fs) > 0 {
				after = fs
				break
			}
			time.Sleep(250 * time.Millisecond)
		}
		require.Len(t, after, 1, "the real backfill persists the finding")
		require.Equal(t, "cve_watcher", after[0].FindingKind)
	})
}

// requireEventually polls cond until it holds or the timeout elapses,
// without require inside the loop (it may run off the main goroutine's
// expectations).
func requireEventually(t *testing.T, timeout time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	require.FailNow(t, "condition never satisfied", msg)
}
