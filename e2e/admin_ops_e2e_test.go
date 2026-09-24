//go:build e2e

package e2e

import (
	"context"
	"net/http"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// Local response shapes for the admin & operations endpoints (BP-54, BP-55).

type adminStatus struct {
	Projects              int64      `json:"projects"`
	Users                 int64      `json:"users"`
	OpenFindings          int64      `json:"open_findings"`
	Reports               int64      `json:"reports"`
	OldestSettledReportAt *time.Time `json:"oldest_settled_report_at"`
}

type retentionPreview struct {
	OlderThanDays int       `json:"older_than_days"`
	Cutoff        time.Time `json:"cutoff"`
	StaleReports  int64     `json:"stale_reports"`
}

type retentionResult struct {
	OlderThanDays    int      `json:"older_than_days"`
	DeletedReports   int64    `json:"deleted_reports"`
	DeletedReportIDs []string `json:"deleted_report_ids"`
}

// backdateProjectReports ages a project's reports so a retention window can
// observe them. The API exposes no way to set report age, so the test
// arranges that precondition directly in the test database; the retention
// logic itself still runs against the real rows and real SQL.
func backdateProjectReports(t *testing.T, slug string) {
	t.Helper()
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	tag, err := pool.Exec(ctx,
		`UPDATE reports
		    SET created_at = now() - interval '3 days',
		        completed_at = now() - interval '3 days'
		  WHERE project_id = (SELECT id FROM projects WHERE slug = $1)`, slug)
	require.NoError(t, err)
	require.NotZero(t, tag.RowsAffected(), "the project's settled reports must exist")
}

// TestE2E_AdminStatusAndRetention walks the admin operations: the
// observability snapshot, retention preview/purge round trips, and the
// purge invariants (findings survive their reports; fresh reports are
// retained; a re-purge deletes nothing).
func TestE2E_AdminStatusAndRetention(t *testing.T) {
	slug := newProject(t, "admin-ops")
	key := mintKey(t, slug)
	ingestFixture(t, slug, key, "high-medium.sarif.json")
	ingestFixture(t, slug, key, "medium.sarif.json")
	viewerToken := login(t, "e2e-viewer@example.com", adminPass)

	t.Run("admin status is a session-admin snapshot", func(t *testing.T) {
		status, raw := doJSON(t, http.MethodGet, "/api/v1/admin/status", viewerToken, nil)
		require.Equal(t, http.StatusForbidden, status)
		require.Equal(t, "insufficient_role", errorCode(t, raw),
			"a non-admin session is refused")

		status, raw = doJSON(t, http.MethodGet, "/api/v1/admin/status", key, nil)
		require.Equal(t, http.StatusForbidden, status)
		require.Equal(t, "insufficient_role", errorCode(t, raw),
			"project keys never hold platform authority")

		snapshot := request[adminStatus](t, http.MethodGet,
			"/api/v1/admin/status", adminToken, nil, http.StatusOK)
		require.GreaterOrEqual(t, snapshot.Projects, int64(1))
		require.GreaterOrEqual(t, snapshot.Users, int64(2))
		require.GreaterOrEqual(t, snapshot.Reports, int64(2))
		require.GreaterOrEqual(t, snapshot.OpenFindings, int64(1))
		require.NotNil(t, snapshot.OldestSettledReportAt,
			"settled reports exist, so the oldest is known")

		// The CLI authenticates with the token in API_KEY: a project key
		// is refused (platform authority stays with sessions) while a
		// session token drives the same snapshot.
		_, stderr, exit := runBin(t, cliBin,
			[]string{"API_URL=" + baseURL, "API_KEY=" + key},
			"admin", "status")
		require.Equal(t, 2, exit, "a project key cannot read platform status; stderr:\n%s", stderr)
		require.NotEmpty(t, stderr)

		stdout, stderr, exit := runBin(t, cliBin,
			[]string{"API_URL=" + baseURL, "API_KEY=" + adminToken},
			"admin", "status")
		require.Equal(t, 0, exit, "a session token drives admin status; stderr:\n%s", stderr)
		require.Contains(t, stdout, "projects=")
		require.Contains(t, stdout, "open_findings=")

		stdout, stderr, exit = runBin(t, cliBin,
			[]string{"API_URL=" + baseURL, "API_KEY=" + adminToken},
			"admin", "status", "--format", "json")
		require.Equal(t, 0, exit, "stderr:\n%s", stderr)
		require.Contains(t, stdout, `"open_findings"`)
	})

	t.Run("retention windows are validated", func(t *testing.T) {
		for _, days := range []string{"0", "3651", "not-a-number"} {
			status, raw := doJSON(t, http.MethodGet,
				"/api/v1/admin/retention/preview?days="+days, adminToken, nil)
			require.Equal(t, http.StatusBadRequest, status)
			require.Equal(t, "invalid_window", errorCode(t, raw))
		}

		for _, days := range []int{0, 3651} {
			status, raw := doJSON(t, http.MethodPost,
				"/api/v1/admin/retention/purge", adminToken,
				map[string]int{"older_than_days": days})
			require.Equal(t, http.StatusBadRequest, status)
			require.Equal(t, "invalid_window", errorCode(t, raw))
		}

		status, raw := doJSON(t, http.MethodGet,
			"/api/v1/admin/retention/preview?days=1", viewerToken, nil)
		require.Equal(t, http.StatusForbidden, status)
		require.Equal(t, "insufficient_role", errorCode(t, raw))

		status, raw = doJSON(t, http.MethodPost,
			"/api/v1/admin/retention/purge", key,
			map[string]int{"older_than_days": 1})
		require.Equal(t, http.StatusForbidden, status)
		require.Equal(t, "insufficient_role", errorCode(t, raw),
			"project keys never hold platform authority")

		_, stderr, exit := runBin(t, cliBin,
			[]string{"API_URL=" + baseURL, "API_KEY=" + adminToken},
			"admin", "retention", "preview")
		require.Equal(t, 2, exit, "--days is required; stderr:\n%s", stderr)
		require.Contains(t, stderr, "--days is required")
	})

	t.Run("purge deletes only settled reports past the window", func(t *testing.T) {
		fresh := request[retentionPreview](t, http.MethodGet,
			"/api/v1/admin/retention/preview?days=1", adminToken, nil, http.StatusOK)
		require.Zero(t, fresh.StaleReports,
			"just-ingested reports are younger than the window")

		backdateProjectReports(t, slug)

		aged := request[retentionPreview](t, http.MethodGet,
			"/api/v1/admin/retention/preview?days=1", adminToken, nil, http.StatusOK)
		require.EqualValues(t, 2, aged.StaleReports,
			"preview counts exactly this project's aged reports")

		stdout, stderr, exit := runBin(t, cliBin,
			[]string{"API_URL=" + baseURL, "API_KEY=" + adminToken},
			"admin", "retention", "preview", "--days", "1")
		require.Equal(t, 0, exit, "stderr:\n%s", stderr)
		require.Contains(t, stdout, "2 settled report(s) older than 1 day(s)")

		purged := request[retentionResult](t, http.MethodPost,
			"/api/v1/admin/retention/purge", adminToken,
			map[string]int{"older_than_days": 1}, http.StatusOK)
		require.EqualValues(t, 2, purged.DeletedReports,
			"preview and purge agree on the count")
		require.Len(t, purged.DeletedReportIDs, 2)

		after := request[retentionPreview](t, http.MethodGet,
			"/api/v1/admin/retention/preview?days=1", adminToken, nil, http.StatusOK)
		require.Zero(t, after.StaleReports)

		reports := request[[]projectReport](t, http.MethodGet,
			"/api/v1/projects/"+slug+"/reports", adminToken, nil, http.StatusOK)
		require.Empty(t, reports, "the purged reports are gone")

		findings := listFindings(t, slug)
		require.Len(t, findings, 2,
			"findings survive their reports — purge cascades occurrences, not analysis")

		stdout, stderr, exit = runBin(t, cliBin,
			[]string{"API_URL=" + baseURL, "API_KEY=" + adminToken},
			"admin", "retention", "purge", "--days", "1", "--format", "json")
		require.Equal(t, 0, exit, "stderr:\n%s", stderr)
		require.Contains(t, stdout, `"deleted_reports": 0`,
			"a re-purge over an empty window deletes nothing")
	})
}

// projectReport is the report-list row this test decodes.
type projectReport struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

// bootServer runs the real server binary with the given environment and
// returns its exit code and combined output. A timeout means the server
// *started* — a failure when the environment was meant to be rejected.
func bootServer(t *testing.T, env ...string) (int, string) {
	t.Helper()
	port, err := freePort()
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, serverBin)
	cmd.Dir = repoRoot
	cmd.Env = cleanEnv(append(env, "SERVER_ADDR=127.0.0.1:"+strconv.Itoa(port))...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("server started despite an invalid environment; output:\n%s", out)
	}
	if err != nil {
		exitErr, ok := err.(*exec.ExitError)
		require.Truef(t, ok, "run server: %v", err)
		return exitErr.ExitCode(), string(out)
	}
	return 0, string(out)
}

// baseBootEnv is the minimal valid environment; each case replaces the one
// variable it invalidates (duplicate keys lose to the first occurrence, so
// a key must never appear twice).
func baseBootEnv(jwt string) []string {
	env := []string{
		"DATABASE_URL=" + dsn,
		"LOG_LEVEL=info",
		"DB_MIGRATE=false",
		"RATE_LIMIT_ENABLED=false",
		"WATCHER_ENABLE=false",
	}
	if jwt != "" {
		env = append(env, "JWT_SECRET="+jwt)
	}
	return env
}

// TestE2E_ServerConfigBootContract pins the boot-time environment
// contracts: an invalid lifecycle sweep interval refuses to start the
// server with an explicit reason, and a missing JWT secret is fatal —
// a server that boots without a signing key would be a security defect.
func TestE2E_ServerConfigBootContract(t *testing.T) {
	for _, bad := range []string{"banana", "0s", "-5s"} {
		bad := bad
		t.Run("sweep interval "+bad+" refuses to boot", func(t *testing.T) {
			exit, out := bootServer(t,
				append(baseBootEnv(randomHex(48)), "LIFECYCLE_SWEEP_INTERVAL="+bad)...)
			require.NotZero(t, exit,
				"an invalid sweep interval must stop the boot; output:\n%s", out)
			require.Contains(t, out,
				"LIFECYCLE_SWEEP_INTERVAL must be a positive duration")
		})
	}

	t.Run("a missing JWT secret is fatal", func(t *testing.T) {
		exit, out := bootServer(t, baseBootEnv("")...)
		require.NotZero(t, exit,
			"a server without a signing secret must refuse to start; output:\n%s", out)
		require.Contains(t, out, "JWT_SECRET is required")
	})
}
