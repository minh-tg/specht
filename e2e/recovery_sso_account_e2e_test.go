//go:build e2e

package e2e

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// An account that signs in only through the identity provider has no local
// password. The host reset command refuses it, as the reset link does, and
// gives it one only when the operator says so, for an IdP that is down.
func TestE2E_RecoveryResetOfAnSSOOnlyAccount(t *testing.T) {
	const email = "e2e-sso-recovery@example.com"
	t.Cleanup(func() { fakes.idp.setEmail(e2eSSOEmail) })
	fakes.idp.setEmail(email)
	status, location, cookies := ssoExchange(t, "")
	ssoToken(t, status, location, cookies)

	t.Run("it is refused by default and nothing changes", func(t *testing.T) {
		code, stdout, stderr := serverCommand(t, "", "reset-password", email)
		require.Equal(t, 1, code, stderr)
		require.Contains(t, stderr, "identity provider")
		require.Contains(t, stderr, "--allow-sso-account")
		require.NotContains(t, stdout, "New password:")
		require.Contains(t, stdout, "audit=user.reset_password")
		require.Contains(t, stdout, "outcome=failure")
	})

	t.Run("the override gives it a working password and is audited", func(t *testing.T) {
		code, stdout, stderr := serverCommand(t, "", "reset-password", email, "--allow-sso-account")
		require.Equal(t, 0, code, stderr)
		var generated, auditLine string
		for _, line := range strings.Split(stdout, "\n") {
			if rest, ok := strings.CutPrefix(line, "New password: "); ok {
				generated = strings.TrimSpace(rest)
			}
			if strings.Contains(line, "audit=user.reset_password") {
				auditLine = line
			}
		}
		require.NotEmpty(t, generated, stdout)
		require.Contains(t, stdout, "now also has a local password")
		require.Contains(t, auditLine, "outcome=success")
		require.Contains(t, auditLine, "allow-sso-account")

		token := login(t, email, generated)
		me := request[userProfile](t, http.MethodGet, "/api/v1/me", token, nil, http.StatusOK)
		require.Equal(t, email, me.Email)
	})
}
