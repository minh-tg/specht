//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// freshServer is a second server process on its own empty database, the state
// a self-hoster is in right after the first docker compose up. It can be
// restarted on the same database, as an operator does after editing the
// environment.
type freshServer struct {
	url     string
	log     string
	dsn     string
	cmd     *exec.Cmd
	done    chan error
	logFile *os.File
}

func startFreshServer(t *testing.T, dbName string, extraEnv ...string) *freshServer {
	t.Helper()
	ctx := context.Background()

	admin, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	_, err = admin.Exec(ctx, "CREATE DATABASE "+dbName)
	require.NoError(t, err)
	require.NoError(t, admin.Close(ctx))

	freshDSN := strings.Replace(dsn, "/specht_e2e?", "/"+dbName+"?", 1)
	require.NotEqual(t, dsn, freshDSN)

	logPath := filepath.Join(t.TempDir(), "server.log")
	logFile, err := os.Create(logPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = logFile.Close() })

	srv := &freshServer{log: logPath, dsn: freshDSN, logFile: logFile}
	t.Cleanup(srv.stop)
	srv.start(t, extraEnv...)
	return srv
}

// start launches the server binary against the server's database and waits
// until it is healthy.
func (s *freshServer) start(t *testing.T, extraEnv ...string) {
	t.Helper()
	port, err := freePort()
	require.NoError(t, err)
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	env := cleanEnv(append([]string{
		"DATABASE_URL=" + s.dsn,
		"JWT_SECRET=" + randomHex(48),
		"SERVER_ADDR=" + addr,
		"LOG_LEVEL=info",
		"DB_MIGRATE=true",
		"RATE_LIMIT_ENABLED=false",
		// Setup, login and the rest share the per-IP credential budget; the
		// walk-through below makes more calls than the default allows.
		"RATE_LIMIT_LOGIN_PER_MINUTE=100000",
		"RATE_LIMIT_LOGIN_BURST=100000",
	}, extraEnv...)...)

	cmd := exec.Command(serverBin)
	cmd.Dir = repoRoot
	cmd.Env = env
	cmd.Stdout = s.logFile
	cmd.Stderr = s.logFile
	require.NoError(t, cmd.Start())
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	s.cmd, s.done, s.url = cmd, done, "http://"+addr

	require.Eventually(t, func() bool {
		resp, err := http.Get(s.url + "/api/v1/health")
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, 60*time.Second, 150*time.Millisecond, "fresh server never became healthy:\n%s", s.readLog())
}

// stop ends the server process and waits for it. It is safe to call twice.
func (s *freshServer) stop() {
	if s.cmd == nil {
		return
	}
	_ = s.cmd.Process.Signal(os.Interrupt)
	select {
	case <-s.done:
	case <-time.After(10 * time.Second):
		_ = s.cmd.Process.Kill()
		<-s.done
	}
	s.cmd = nil
}

// restart stops the server and starts it again on the same database with a
// new environment.
func (s *freshServer) restart(t *testing.T, extraEnv ...string) {
	t.Helper()
	s.stop()
	s.start(t, extraEnv...)
}

func (s *freshServer) readLog() string {
	raw, _ := os.ReadFile(s.log)
	return string(raw)
}

func (s *freshServer) do(t *testing.T, method, path, token string, body any) (int, http.Header, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		require.NoError(t, err)
		reader = strings.NewReader(string(raw))
	}
	req, err := http.NewRequest(method, s.url+path, reader)
	require.NoError(t, err)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, resp.Header, out
}

func (s *freshServer) setupRequired(t *testing.T) (bool, http.Header) {
	t.Helper()
	status, header, raw := s.do(t, http.MethodGet, "/api/v1/capabilities", "", nil)
	require.Equal(t, http.StatusOK, status, string(raw))
	var body struct {
		Setup struct {
			Required bool `json:"required"`
		} `json:"setup"`
	}
	require.NoError(t, json.Unmarshal(raw, &body), string(raw))
	return body.Setup.Required, header
}

var setupTokenInLog = regexp.MustCompile(`setup_token=(\S+)`)

// TestE2E_FirstRunSetup walks a fresh install with registration left unset:
// signup is closed, but the setup token still creates the first administrator.
func TestE2E_FirstRunSetup(t *testing.T) {
	srv := startFreshServer(t, "specht_setup_logged")

	status, _, raw := srv.do(t, http.MethodGet, "/api/v1/capabilities", "", nil)
	require.Equal(t, http.StatusOK, status, string(raw))
	var capabilities struct {
		Registration struct {
			Enabled bool `json:"enabled"`
		} `json:"registration"`
		Setup struct {
			Required bool `json:"required"`
		} `json:"setup"`
	}
	require.NoError(t, json.Unmarshal(raw, &capabilities), string(raw))
	require.False(t, capabilities.Registration.Enabled,
		"capabilities must reflect the closed default so the UI hides signup")
	require.True(t, capabilities.Setup.Required)

	status, _, raw = srv.do(t, http.MethodPost, "/api/v1/auth/register", "", map[string]any{
		"email": "walkin@example.com", "password": "correct-horse-battery",
	})
	require.Equal(t, http.StatusForbidden, status, string(raw))

	required, header := srv.setupRequired(t)
	require.True(t, required, "a server with no admin asks for setup")
	require.Equal(t, "no-store", header.Get("Cache-Control"))

	match := setupTokenInLog.FindStringSubmatch(srv.readLog())
	require.Len(t, match, 2, "the generated token is logged once at startup:\n%s", srv.readLog())
	token := strings.Trim(match[1], `"`)

	account := map[string]any{"email": "root@example.com", "password": "correct-horse-battery", "display_name": "Root"}

	status, _, _ = srv.do(t, http.MethodPost, "/api/v1/setup", "", merge(account, "token", "not-the-token"))
	require.Equal(t, http.StatusForbidden, status)
	status, _, _ = srv.do(t, http.MethodPost, "/api/v1/setup", "", merge(account, "token", ""))
	require.Equal(t, http.StatusForbidden, status)
	status, _, raw = srv.do(t, http.MethodPost, "/api/v1/setup", "", merge(map[string]any{"email": "root@example.com", "password": "short"}, "token", token))
	require.Equal(t, http.StatusBadRequest, status, string(raw))

	status, _, raw = srv.do(t, http.MethodPost, "/api/v1/setup", "", merge(account, "token", token))
	require.Equal(t, http.StatusCreated, status, string(raw))
	var session struct {
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
	}
	require.NoError(t, json.Unmarshal(raw, &session))
	require.NotEmpty(t, session.Token)
	require.NotEmpty(t, session.RefreshToken)

	// The new session is a global admin: it can read the admin-only user list.
	status, _, raw = srv.do(t, http.MethodGet, "/api/v1/users", session.Token, nil)
	require.Equal(t, http.StatusOK, status, string(raw))
	require.Contains(t, string(raw), "root@example.com")

	// The password works for a normal login afterwards.
	status, _, raw = srv.do(t, http.MethodPost, "/api/v1/auth/login", "", map[string]any{"email": "root@example.com", "password": "correct-horse-battery"})
	require.Equal(t, http.StatusOK, status, string(raw))

	// The door is closed: same token, and the capabilities say so.
	status, _, _ = srv.do(t, http.MethodPost, "/api/v1/setup", "", merge(map[string]any{"email": "other@example.com", "password": "correct-horse-battery"}, "token", token))
	require.Equal(t, http.StatusNotFound, status)
	required, header = srv.setupRequired(t)
	require.False(t, required)
	require.Equal(t, "public, max-age=60", header.Get("Cache-Control"))
	status, _, raw = srv.do(t, http.MethodGet, "/api/v1/capabilities", "", nil)
	require.Equal(t, http.StatusOK, status, string(raw))
	require.NoError(t, json.Unmarshal(raw, &capabilities), string(raw))
	require.False(t, capabilities.Registration.Enabled,
		"signup remains closed after first-run setup completes")
	require.False(t, capabilities.Setup.Required)
}

// TestE2E_FirstRunSetupWithOperatorToken covers scripted installs: the token
// comes from SETUP_TOKEN and its value never reaches the log.
func TestE2E_FirstRunSetupWithOperatorToken(t *testing.T) {
	const token = "scripted-install-token-0001"
	srv := startFreshServer(t, "specht_setup_env", "SETUP_TOKEN="+token)

	require.NotContains(t, srv.readLog(), token, "an operator-chosen token is not echoed to the log")
	required, _ := srv.setupRequired(t)
	require.True(t, required)

	status, _, raw := srv.do(t, http.MethodPost, "/api/v1/setup", "", map[string]any{
		"token": token, "email": "ops@example.com", "password": "correct-horse-battery",
	})
	require.Equal(t, http.StatusCreated, status, string(raw))
}

// TestE2E_SetupSurvivesAStrangerRegisteringFirst covers a fresh server with
// registration open: someone signs up before the operator. That account is a
// normal user, so it must not close setup, and the operator can still create
// the first admin with the token. A registered address cannot be reused.
func TestE2E_SetupSurvivesAStrangerRegisteringFirst(t *testing.T) {
	const token = "squatter-race-token-0001"
	srv := startFreshServer(t, "specht_setup_squat", "SETUP_TOKEN="+token, "REGISTRATION_ENABLED=true")

	status, _, raw := srv.do(t, http.MethodPost, "/api/v1/auth/register", "", map[string]any{
		"email": "stranger@example.com", "password": "correct-horse-battery",
	})
	require.Equal(t, http.StatusCreated, status, string(raw))

	required, _ := srv.setupRequired(t)
	require.True(t, required, "a registered non-admin must not close setup")

	status, _, raw = srv.do(t, http.MethodPost, "/api/v1/setup", "", map[string]any{
		"token": token, "email": "stranger@example.com", "password": "correct-horse-battery",
	})
	require.Equal(t, http.StatusConflict, status, "the address is taken: "+string(raw))
	required, _ = srv.setupRequired(t)
	require.True(t, required, "a refused setup leaves setup open")

	status, _, raw = srv.do(t, http.MethodPost, "/api/v1/setup", "", map[string]any{
		"token": token, "email": "ops@example.com", "password": "correct-horse-battery",
	})
	require.Equal(t, http.StatusCreated, status, string(raw))

	required, _ = srv.setupRequired(t)
	require.False(t, required, "the first admin closes setup")
	status, _, _ = srv.do(t, http.MethodPost, "/api/v1/setup", "", map[string]any{
		"token": token, "email": "again@example.com", "password": "correct-horse-battery",
	})
	require.Equal(t, http.StatusNotFound, status)
}

// TestE2E_AdminEmailsPromotesOnlyAccountsThatProvedTheAddress restarts one
// server with ADMIN_EMAILS naming a registered account and the account
// first-run setup created. Registration proves nothing, so the registered
// account stays a normal user and the log says why; the setup account was
// vouched for by the setup token, so it is promoted back after a demotion.
func TestE2E_AdminEmailsPromotesOnlyAccountsThatProvedTheAddress(t *testing.T) {
	const token = "admin-emails-token-00001"
	srv := startFreshServer(t, "specht_admin_emails", "SETUP_TOKEN="+token, "REGISTRATION_ENABLED=true")

	// A stranger registers the address the operator is about to list.
	status, _, raw := srv.do(t, http.MethodPost, "/api/v1/auth/register", "", map[string]any{
		"email": "ceo@example.com", "password": "correct-horse-battery",
	})
	require.Equal(t, http.StatusCreated, status, string(raw))

	// The operator sets up the server, makes a second admin, and is then
	// demoted, as when an operator hands over and wants the role back later.
	status, _, raw = srv.do(t, http.MethodPost, "/api/v1/setup", "", map[string]any{
		"token": token, "email": "ops@example.com", "password": "correct-horse-battery",
	})
	require.Equal(t, http.StatusCreated, status, string(raw))
	var ops authResponse
	require.NoError(t, json.Unmarshal(raw, &ops))
	status, _, raw = srv.do(t, http.MethodPost, "/api/v1/auth/register", "", map[string]any{
		"email": "deputy@example.com", "password": "correct-horse-battery",
	})
	require.Equal(t, http.StatusCreated, status, string(raw))
	var deputy authResponse
	require.NoError(t, json.Unmarshal(raw, &deputy))
	status, _, raw = srv.do(t, http.MethodPut, "/api/v1/users/"+deputy.UserID+"/role", ops.Token, map[string]string{"role": "admin"})
	require.Equal(t, http.StatusOK, status, string(raw))
	status, _, raw = srv.do(t, http.MethodPut, "/api/v1/users/"+ops.UserID+"/role", ops.Token, map[string]string{"role": "member"})
	require.Equal(t, http.StatusOK, status, string(raw))

	srv.restart(t, "REGISTRATION_ENABLED=true", "ADMIN_EMAILS=CEO@Example.com, ops@example.com, nobody@example.com")

	roleOf := func(email string) string {
		t.Helper()
		status, _, raw := srv.do(t, http.MethodPost, "/api/v1/auth/login", "", map[string]any{
			"email": email, "password": "correct-horse-battery",
		})
		require.Equal(t, http.StatusOK, status, string(raw))
		var session authResponse
		require.NoError(t, json.Unmarshal(raw, &session))
		status, _, raw = srv.do(t, http.MethodGet, "/api/v1/me", session.Token, nil)
		require.Equal(t, http.StatusOK, status, string(raw))
		var me struct {
			Role string `json:"role"`
		}
		require.NoError(t, json.Unmarshal(raw, &me))
		return me.Role
	}
	require.Equal(t, "member", roleOf("ceo@example.com"), "a registered account is never promoted by ADMIN_EMAILS")
	require.Equal(t, "admin", roleOf("ops@example.com"), "the account first-run setup created is promoted")

	log := srv.readLog()
	require.Contains(t, log, "not promoted")
	require.Contains(t, log, "c***@example.com", "the warning names the address, masked")
	for _, line := range strings.Split(log, "\n") {
		if strings.Contains(line, "admin bootstrap") {
			require.NotContains(t, line, "ceo@example.com", "the bootstrap lines mask the address")
		}
	}
	require.Equal(t, 1, strings.Count(log, "never proved this address"), "one warning, only for the registered account")
}

// TestE2E_SetupIsClosedOnAnEstablishedServer checks the shared server, which
// already has accounts: no setup route, no setup screen.
func TestE2E_SetupIsClosedOnAnEstablishedServer(t *testing.T) {
	status, raw := doJSON(t, http.MethodPost, "/api/v1/setup", "", map[string]any{
		"token": "anything-at-all-0000", "email": "x@example.com", "password": "correct-horse-battery",
	})
	require.Equal(t, http.StatusNotFound, status, string(raw))

	resp, err := http.Get(baseURL + "/api/v1/capabilities")
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Contains(t, string(body), `"setup":{"required":false}`)
}

func merge(base map[string]any, key string, value any) map[string]any {
	out := make(map[string]any, len(base)+1)
	for k, v := range base {
		out[k] = v
	}
	out[key] = value
	return out
}
