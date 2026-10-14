//go:build e2e

package e2e

import (
	"bytes"
	"errors"
	"net/http"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// serverCommand runs one subcommand of the real server binary against the
// suite's database, the way an operator would inside the container.
func serverCommand(t *testing.T, stdin string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	cmd := exec.Command(serverBin, args...)
	cmd.Dir = repoRoot
	cmd.Env = cleanEnv(
		"DATABASE_URL="+dsn,
		"JWT_SECRET="+randomHex(48),
		"LOG_LEVEL=info",
		"DB_MIGRATE=false",
	)
	cmd.Stdin = strings.NewReader(stdin)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exit):
		code = exit.ExitCode()
	default:
		t.Fatalf("run %v: %v", args, err)
	}
	return code, out.String(), errOut.String()
}

// TestE2E_AdminRecoveryCommands proves the way back in when the only admin has
// lost access: the host-side commands reset a password and grant the admin
// role, and they end the account's sessions.
func TestE2E_AdminRecoveryCommands(t *testing.T) {
	const email = "e2e-viewer@example.com"
	me := request[userProfile](t, http.MethodGet, "/api/v1/me", login(t, email, adminPass), nil, http.StatusOK)

	// The account is shared with other tests: put it back whatever happens.
	t.Cleanup(func() {
		serverCommand(t, adminPass+"\n", "reset-password", email, "--password-stdin")
		doJSON(t, http.MethodPut, "/api/v1/users/"+me.ID+"/role", adminToken, map[string]string{"role": "member"})
	})

	t.Run("an unknown address is reported and nothing changes", func(t *testing.T) {
		code, _, stderr := serverCommand(t, "", "reset-password", "nobody-here@example.com")
		require.Equal(t, 1, code, stderr)
		require.Contains(t, stderr, "no account has that email address")
		login(t, email, adminPass)
	})

	t.Run("the seeded system account is refused", func(t *testing.T) {
		code, _, stderr := serverCommand(t, "", "reset-password", "system@specht.local")
		require.Equal(t, 1, code, stderr)
		require.Contains(t, stderr, "system account")
	})

	t.Run("a usage error exits with 2 and touches nothing", func(t *testing.T) {
		code, _, stderr := serverCommand(t, "", "reset-password")
		require.Equal(t, 2, code)
		require.Contains(t, stderr, "usage")
	})

	t.Run("reset-password gives a working password and ends the old sessions", func(t *testing.T) {
		old := request[authResponse](t, http.MethodPost, "/api/v1/auth/login", "",
			map[string]string{"email": email, "password": adminPass}, http.StatusOK)

		code, stdout, stderr := serverCommand(t, "", "reset-password", strings.ToUpper(email))
		require.Equal(t, 0, code, stderr)
		var generated string
		for _, line := range strings.Split(stdout, "\n") {
			if rest, ok := strings.CutPrefix(line, "New password: "); ok {
				generated = strings.TrimSpace(rest)
			}
		}
		require.NotEmpty(t, generated, "the command prints the generated password: %q", stdout)

		status, _ := doJSON(t, http.MethodGet, "/api/v1/me", old.Token, nil)
		require.Equal(t, http.StatusUnauthorized, status, "the old access token ends")
		status, raw := doJSON(t, http.MethodPost, "/api/v1/auth/refresh", "", map[string]string{"refresh_token": old.RefreshToken})
		require.GreaterOrEqual(t, status, 400, "the old refresh token ends: "+string(raw))
		status, _ = doJSON(t, http.MethodPost, "/api/v1/auth/login", "",
			map[string]string{"email": email, "password": adminPass})
		require.Equal(t, http.StatusUnauthorized, status, "the old password stops working")

		token := login(t, email, generated)
		require.Equal(t, me.ID, request[userProfile](t, http.MethodGet, "/api/v1/me", token, nil, http.StatusOK).ID)
	})

	t.Run("reset-password can read the password from standard input", func(t *testing.T) {
		code, stdout, stderr := serverCommand(t, "a-chosen-password-9\n", "reset-password", email, "--password-stdin")
		require.Equal(t, 0, code, stderr)
		require.NotContains(t, stdout, "a-chosen-password-9", "a chosen password is never echoed")
		login(t, email, "a-chosen-password-9")
	})

	t.Run("grant-admin promotes the account", func(t *testing.T) {
		before := login(t, email, "a-chosen-password-9")
		require.Equal(t, "member", request[userProfile](t, http.MethodGet, "/api/v1/me", before, nil, http.StatusOK).Role)

		code, _, stderr := serverCommand(t, "", "grant-admin", email)
		require.Equal(t, 0, code, stderr)

		status, _ := doJSON(t, http.MethodGet, "/api/v1/me", before, nil)
		require.Equal(t, http.StatusUnauthorized, status, "the role change starts a new token generation")
		after := login(t, email, "a-chosen-password-9")
		require.Equal(t, "admin", request[userProfile](t, http.MethodGet, "/api/v1/me", after, nil, http.StatusOK).Role)
	})
}
