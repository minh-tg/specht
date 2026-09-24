//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/minh-tg/specht/internal/db"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// Shared stack: one real PostgreSQL, one real cmd/server process, and
// pre-built adapter/CLI binaries. Every test drives the public contracts
// exactly as a self-hoster (HTTP) or a CI pipeline (binaries) would.

var (
	baseURL    string
	adminEmail string
	adminPass  string
	adminToken string

	serverBin  string
	adapterBin string
	cliBin     string

	repoRoot   string
	tmpDir     string
	dsn        string
	container  testcontainers.Container
	serverCmd  *exec.Cmd
	serverLog  *os.File
	serverDone chan error
)

func TestMain(m *testing.M) {
	os.Exit(runE2E(m))
}

func runE2E(m *testing.M) int {
	var err error
	repoRoot, err = filepath.Abs("..")
	if err != nil {
		fmt.Fprintf(os.Stderr, "resolve repo root: %v\n", err)
		return 1
	}
	tmpDir, err = os.MkdirTemp("", "specht-e2e-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "temp dir: %v\n", err)
		return 1
	}
	defer os.RemoveAll(tmpDir)

	serverLog, err = os.OpenFile(filepath.Join(tmpDir, "server.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "server log: %v\n", err)
		return 1
	}
	defer serverLog.Close()

	if err := startDatabase(); err != nil {
		fmt.Fprintf(os.Stderr, "database: %v\n", err)
		return 1
	}
	defer stopDatabase()

	if err := buildBinaries(); err != nil {
		fmt.Fprintf(os.Stderr, "build binaries: %v\n", err)
		return 1
	}

	adminEmail = "e2e-admin@example.com"
	adminPass = randomHex(24)

	// Phase 1: boot without ADMIN_EMAILS, create the accounts.
	if err := startServer(""); err != nil {
		fmt.Fprintf(os.Stderr, "server phase 1: %v\n%s\n", err, serverLogTail())
		return 1
	}
	if status, _, err := postJSON(baseURL+"/api/v1/auth/register", "", map[string]string{
		"email": adminEmail, "password": adminPass,
	}); err != nil || status != http.StatusCreated {
		fmt.Fprintf(os.Stderr, "register admin: status=%d err=%v\n%s\n", status, err, serverLogTail())
		stopServer()
		return 1
	}
	if status, _, err := postJSON(baseURL+"/api/v1/auth/register", "", map[string]string{
		"email": "e2e-viewer@example.com", "password": adminPass,
	}); err != nil || status != http.StatusCreated {
		fmt.Fprintf(os.Stderr, "register viewer: status=%d err=%v\n", status, err)
		stopServer()
		return 1
	}
	stopServer()

	// Phase 2: restart with ADMIN_EMAILS so bootstrapAdmins promotes the
	// first account — the documented production promotion path.
	if err := startServer(adminEmail); err != nil {
		fmt.Fprintf(os.Stderr, "server phase 2: %v\n%s\n", err, serverLogTail())
		return 1
	}
	defer stopServer()

	status, body, err := postJSON(baseURL+"/api/v1/auth/login", "", map[string]string{
		"email": adminEmail, "password": adminPass,
	})
	if err != nil || status != http.StatusOK {
		fmt.Fprintf(os.Stderr, "login admin: status=%d err=%v body=%s\n%s\n", status, err, body, serverLogTail())
		return 1
	}
	var auth struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &auth); err != nil || auth.Token == "" {
		fmt.Fprintf(os.Stderr, "login admin: no token in %s\n", body)
		return 1
	}
	adminToken = auth.Token

	return m.Run()
}

func startDatabase() error {
	ctx := context.Background()
	req := testcontainers.ContainerRequest{
		Image:        "postgres:17-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "specht",
			"POSTGRES_PASSWORD": "specht",
			"POSTGRES_DB":       "specht_e2e",
		},
		WaitingFor: wait.ForLog("database system is ready to accept connections").
			WithOccurrence(2).
			WithStartupTimeout(60 * time.Second),
	}
	var err error
	container, err = testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return fmt.Errorf("start postgres: %w", err)
	}
	host, err := container.Host(ctx)
	if err != nil {
		return fmt.Errorf("postgres host: %w", err)
	}
	port, err := container.MappedPort(ctx, "5432")
	if err != nil {
		return fmt.Errorf("postgres port: %w", err)
	}
	dsn = fmt.Sprintf("postgres://specht:specht@%s:%s/specht_e2e?sslmode=disable", host, port.Port())
	if err := db.RunMigrations(dsn, filepath.Join(repoRoot, "migrations")); err != nil {
		return fmt.Errorf("migrations: %w", err)
	}
	return nil
}

func stopDatabase() {
	if container != nil {
		_ = container.Terminate(context.Background())
	}
}

func buildBinaries() error {
	for _, target := range []struct{ out, pkg string }{
		{filepath.Join(tmpDir, "specht-server"), "./cmd/server"},
		{filepath.Join(tmpDir, "specht-adapter"), "./cmd/adapter"},
		{filepath.Join(tmpDir, "specht"), "./cmd/specht"},
	} {
		cmd := exec.Command("go", "build", "-o", target.out, target.pkg)
		cmd.Dir = repoRoot
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("go build %s: %w\n%s", target.pkg, err, out)
		}
	}
	serverBin = filepath.Join(tmpDir, "specht-server")
	adapterBin = filepath.Join(tmpDir, "specht-adapter")
	cliBin = filepath.Join(tmpDir, "specht")
	return nil
}

// startServer boots the real server binary with a swept-up environment:
// caller-provided variables override anything inherited, so CI env (or a
// developer's .env exports) can never leak into the experiment.
func startServer(adminEmails string) error {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		port, err := freePort()
		if err != nil {
			return err
		}
		addr := fmt.Sprintf("127.0.0.1:%d", port)
		env := cleanEnv(
			"DATABASE_URL="+dsn,
			"JWT_SECRET="+randomHex(48),
			"SERVER_ADDR="+addr,
			"LOG_LEVEL=info",
			"DB_MIGRATE=true",
			// Sweep every second so expiry business processes are
			// observable in tests instead of waiting out 5 minutes.
			"LIFECYCLE_SWEEP_INTERVAL=1s",
			"RATE_LIMIT_ENABLED=false",
			"WATCHER_ENABLE=false",
		)
		if adminEmails != "" {
			env = append(env, "ADMIN_EMAILS="+adminEmails)
		}

		cmd := exec.Command(serverBin)
		cmd.Dir = repoRoot // migrations live at repoRoot/migrations
		cmd.Env = env
		cmd.Stdout = serverLog
		cmd.Stderr = serverLog

		if err := cmd.Start(); err != nil {
			lastErr = fmt.Errorf("start process: %w", err)
			continue
		}
		serverCmd = cmd
		serverDone = make(chan error, 1)
		go func() { serverDone <- cmd.Wait() }()
		baseURL = "http://" + addr

		if err := waitHealth(serverDone); err != nil {
			lastErr = err
			stopServer()
			continue
		}
		return nil
	}
	return lastErr
}

func waitHealth(done chan error) error {
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			// The exit signal is consumed here; clear the handle so a
			// later stopServer (retry path) neither blocks nor re-kills.
			serverCmd = nil
			return fmt.Errorf("server exited before healthy: %w\n%s", err, serverLogTail())
		default:
		}
		resp, err := http.Get(baseURL + "/api/v1/health")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(150 * time.Millisecond)
	}
	return fmt.Errorf("server not healthy within 60s\n%s", serverLogTail())
}

func stopServer() {
	if serverCmd == nil {
		return
	}
	_ = serverCmd.Process.Signal(os.Interrupt)
	select {
	case <-serverDone:
	case <-time.After(10 * time.Second):
		_ = serverCmd.Process.Kill()
		select {
		case <-serverDone:
		case <-time.After(2 * time.Second):
			// Process is unreapable; never hang the suite on teardown.
		}
	}
	serverCmd = nil
}

func serverLogTail() string {
	if serverLog == nil {
		return ""
	}
	raw, err := os.ReadFile(serverLog.Name())
	if err != nil || len(raw) == 0 {
		return "(server log empty)"
	}
	if len(raw) > 8192 {
		raw = raw[len(raw)-8192:]
	}
	return "server log tail:\n" + string(raw)
}

// cleanEnv starts from the inherited environment, drops every key we set
// explicitly (so a stale caller value can never win), and appends overrides.
func cleanEnv(overrides ...string) []string {
	managed := map[string]bool{
		"DATABASE_URL": true, "JWT_SECRET": true, "SERVER_ADDR": true,
		"ADMIN_EMAILS": true, "LOG_LEVEL": true, "DB_MIGRATE": true,
		"LIFECYCLE_SWEEP_INTERVAL": true, "RATE_LIMIT_ENABLED": true,
		"WATCHER_ENABLE": true, "API_URL": true, "API_KEY": true,
	}
	var env []string
	for _, kv := range os.Environ() {
		key, _, ok := strings.Cut(kv, "=")
		if ok && managed[key] {
			continue
		}
		env = append(env, kv)
	}
	return append(env, overrides...)
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("reserve port: %w", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func randomHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return hex.EncodeToString(buf)
}

// postJSON posts a JSON body without a *testing.T (usable from TestMain).
func postJSON(path, token string, body any) (int, []byte, error) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(http.MethodPost, path, reader)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, out, nil
}

// doJSON performs one HTTP call and returns status plus raw body. body is
// marshalled when non-nil.
func doJSON(t *testing.T, method, path, token string, body any) (int, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		require.NoError(t, err)
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, baseURL+path, reader)
	require.NoError(t, err)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoErrorf(t, err, "%s %s", method, path)
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, out
}

// request performs one HTTP call and decodes a wantStatus response into T.
func request[T any](t *testing.T, method, path, token string, body any, wantStatus int) T {
	t.Helper()
	status, raw := doJSON(t, method, path, token, body)
	require.Equalf(t, wantStatus, status, "%s %s: body: %s\n%s", method, path, raw, serverLogTail())
	var out T
	require.NoErrorf(t, json.Unmarshal(raw, &out), "%s %s: decode body: %s", method, path, raw)
	return out
}

// login fresh-mints an access token for the given account.
func login(t *testing.T, email, password string) string {
	t.Helper()
	resp := request[authResponse](t, http.MethodPost, "/api/v1/auth/login", "",
		map[string]string{"email": email, "password": password}, http.StatusOK)
	require.NotEmpty(t, resp.Token)
	return resp.Token
}

type authResponse struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	UserID       string `json:"user_id"`
	Email        string `json:"email"`
}

type userProfile struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Role  string `json:"role"`
}

type projectResponse struct {
	ID   string `json:"id"`
	Slug string `json:"slug"`
	Name string `json:"name"`
}

type apiError struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

type findingResponse struct {
	ID              string `json:"id"`
	CurrentSeverity string `json:"current_severity"`
	CurrentTitle    string `json:"current_title"`
	AnalysisState   string `json:"analysis_state"`
	GateEffect      string `json:"gate_effect"`
}

type gateStatus struct {
	ThresholdBreached bool     `json:"threshold_breached"`
	BlockingCount     int64    `json:"blocking_count"`
	BlockedBy         []string `json:"blocked_by"`
	WaivedCount       int      `json:"waived_count"`
}

type ingestResponse struct {
	ReportID          string `json:"report_id"`
	TotalFindings     int    `json:"total_findings"`
	ThresholdBreached bool   `json:"threshold_breached"`
	ScanMode          string `json:"scan_mode"`
}

type triageOutput struct {
	FindingID     string `json:"finding_id"`
	AnalysisState string `json:"analysis_state"`
	GateEffect    string `json:"gate_effect"`
}

type findingEvent struct {
	EventType string  `json:"event_type"`
	UserID    string  `json:"user_id"`
	Comment   *string `json:"comment,omitempty"`
}

type waiverDetail struct {
	ID        string  `json:"id"`
	Enabled   bool    `json:"enabled"`
	ExpiresAt *string `json:"expires_at,omitempty"`
	Targets   []struct {
		FindingID string `json:"finding_id"`
	} `json:"targets"`
}

type waiverEvent struct {
	EventType string          `json:"event_type"`
	Metadata  json.RawMessage `json:"metadata"`
}

type checkMatchResponse struct {
	Matched bool `json:"matched"`
}

type apiKeyResponse struct {
	ID     string `json:"id"`
	RawKey string `json:"raw_key"`
}

// newProject creates a uniquely-slugged project owned by the admin session
// and returns its slug.
func newProject(t *testing.T, label string) string {
	t.Helper()
	slug := fmt.Sprintf("e2e-%s-%s", label, randomHex(4))
	resp := request[projectResponse](t, http.MethodPost, "/api/v1/projects", adminToken,
		map[string]string{"name": slug, "slug": slug}, http.StatusCreated)
	require.Equal(t, slug, resp.Slug)
	return slug
}

// mintKey creates a project API key with the admin session and returns the
// one-time raw key — the same artifact a CI pipeline would receive.
func mintKey(t *testing.T, slug string) string {
	t.Helper()
	resp := request[apiKeyResponse](t, http.MethodPost, "/api/v1/auth/apikeys", adminToken,
		map[string]string{"project": slug, "name": "e2e-" + randomHex(3)}, http.StatusCreated)
	require.True(t, strings.HasPrefix(resp.RawKey, "vuln_"), "raw key: %s", resp.RawKey)
	return resp.RawKey
}

// ingestBody builds the wire payload for a fixture so a test can post the
// same bytes twice (duplicate detection) without re-reading the file.
func ingestBody(t *testing.T, slug, fixture string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", fixture))
	require.NoError(t, err)
	return map[string]any{
		"project":  slug,
		"scanner":  "sarif",
		"raw_data": json.RawMessage(raw),
	}
}

// ingestFixture posts a SARIF fixture through the API with the given token.
func ingestFixture(t *testing.T, slug, token, fixture string) ingestResponse {
	t.Helper()
	return request[ingestResponse](t, http.MethodPost, "/api/v1/reports", token,
		ingestBody(t, slug, fixture), http.StatusCreated)
}

// listFindings returns the project's findings via the admin session.
func listFindings(t *testing.T, slug string) []findingResponse {
	t.Helper()
	return request[[]findingResponse](t, http.MethodGet,
		"/api/v1/projects/"+slug+"/findings?limit=50", adminToken, nil, http.StatusOK)
}

// getGate reads the project gate via the admin session.
func getGate(t *testing.T, slug, query string) gateStatus {
	t.Helper()
	path := "/api/v1/projects/" + slug + "/gate"
	if query != "" {
		path += "?" + query
	}
	return request[gateStatus](t, http.MethodGet, path, adminToken, nil, http.StatusOK)
}

// highFinding returns the single high-severity finding of the fixture set.
func highFinding(t *testing.T, slug string) findingResponse {
	t.Helper()
	findings := listFindings(t, slug)
	var high []findingResponse
	for _, f := range findings {
		if f.CurrentSeverity == "high" {
			high = append(high, f)
		}
	}
	require.Lenf(t, high, 1, "expected exactly one high finding, got %d of %d", len(high), len(findings))
	return high[0]
}

// createWaiver creates a waiver targeting one finding and returns it.
// expiresAt is an RFC3339 timestamp; empty creates a permanent waiver.
func createWaiver(t *testing.T, slug, name, findingID, expiresAt string) waiverDetail {
	t.Helper()
	body := map[string]any{
		"name":        name,
		"description": "e2e waiver",
		"target_ids":  []string{findingID},
	}
	if expiresAt != "" {
		body["expires_at"] = expiresAt
	}
	return request[waiverDetail](t, http.MethodPost,
		"/api/v1/projects/"+slug+"/waivers", adminToken, body, http.StatusCreated)
}

// runBin executes a built binary with a scrubbed environment: inherited
// CI variables (GITHUB_*, CI_*) are dropped so adapter/CLI behavior is
// deterministic, and API_URL/API_KEY come only from overrides.
func runBin(t *testing.T, bin string, overrides []string, args ...string) (string, string, int) {
	t.Helper()
	var env []string
	for _, kv := range os.Environ() {
		key, _, ok := strings.Cut(kv, "=")
		if ok && (strings.HasPrefix(key, "GITHUB_") || strings.HasPrefix(key, "CI_") ||
			key == "API_URL" || key == "API_KEY" || key == "SPECHT_PROJECT") {
			continue
		}
		env = append(env, kv)
	}
	cmd := exec.Command(bin, args...)
	cmd.Dir = repoRoot
	cmd.Env = append(env, overrides...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	exit := 0
	if err != nil {
		exitErr, ok := err.(*exec.ExitError)
		require.Truef(t, ok, "run %s: %v\nstderr: %s", bin, err, stderr.String())
		exit = exitErr.ExitCode()
	}
	return stdout.String(), stderr.String(), exit
}

// eventually polls until cond holds or the timeout elapses.
func eventually(t *testing.T, timeout time.Duration, msg string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s: %s", timeout, msg)
}
