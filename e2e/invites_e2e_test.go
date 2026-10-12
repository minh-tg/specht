//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type inviteBody struct {
	ID          string `json:"id"`
	Role        string `json:"role"`
	Email       string `json:"email"`
	Link        string `json:"link"`
	Token       string `json:"token"`
	UserID      string `json:"user_id"`
	ProjectSlug string `json:"project_slug"`
	ProjectName string `json:"project_name"`
}

func decodeInvite(t *testing.T, raw []byte) inviteBody {
	t.Helper()
	var out inviteBody
	require.NoError(t, json.Unmarshal(raw, &out), string(raw))
	return out
}

// TestE2E_InviteLinks runs the closed-registration story: an admin sets up the
// server, invites a teammate by link, the teammate joins without registration,
// and the link cannot be reused, probed or taken over.
func TestE2E_InviteLinks(t *testing.T) {
	const setupToken = "invite-flow-setup-token-01"
	srv := startFreshServer(t, "specht_invites", "SETUP_TOKEN="+setupToken, "REGISTRATION_ENABLED=false")

	status, _, raw := srv.do(t, http.MethodPost, "/api/v1/setup", "", map[string]any{
		"token": setupToken, "email": "root@example.com", "password": "correct-horse-battery",
	})
	require.Equal(t, http.StatusCreated, status, string(raw))
	adminTok := decodeInvite(t, raw).Token

	status, _, raw = srv.do(t, http.MethodPost, "/api/v1/projects", adminTok, map[string]any{"name": "Payments", "slug": "payments"})
	require.Equal(t, http.StatusCreated, status, string(raw))

	// Registration is closed, so an invite is the only way in.
	status, _, _ = srv.do(t, http.MethodPost, "/api/v1/auth/register", "", map[string]any{"email": "walkin@example.com", "password": "correct-horse-battery"})
	require.Equal(t, http.StatusForbidden, status)

	// Creating a link: validation first.
	status, _, raw = srv.do(t, http.MethodPost, "/api/v1/projects/payments/invites", adminTok, map[string]any{"role": "admin"})
	require.Equal(t, http.StatusBadRequest, status, string(raw))
	status, _, raw = srv.do(t, http.MethodPost, "/api/v1/projects/payments/invites", adminTok, map[string]any{"role": "member", "expires_in_days": 31})
	require.Equal(t, http.StatusBadRequest, status, string(raw))

	status, _, raw = srv.do(t, http.MethodPost, "/api/v1/projects/payments/invites", adminTok, map[string]any{"role": "member"})
	require.Equal(t, http.StatusCreated, status, string(raw))
	open := decodeInvite(t, raw)
	require.True(t, strings.HasPrefix(open.Link, "/invite/"), open.Link)
	openToken := strings.TrimPrefix(open.Link, "/invite/")

	// The list shows the invite but never its link.
	status, _, raw = srv.do(t, http.MethodGet, "/api/v1/projects/payments/invites", adminTok, nil)
	require.Equal(t, http.StatusOK, status)
	require.Contains(t, string(raw), open.ID)
	require.NotContains(t, string(raw), openToken)

	// The accept page learns the project and role, nothing else.
	status, header, raw := srv.do(t, http.MethodGet, "/api/v1/invites/"+openToken, "", nil)
	require.Equal(t, http.StatusOK, status, string(raw))
	require.Equal(t, "no-store", header.Get("Cache-Control"))
	look := decodeInvite(t, raw)
	require.Equal(t, "Payments", look.ProjectName)
	require.Equal(t, "member", look.Role)
	status, _, _ = srv.do(t, http.MethodGet, "/api/v1/invites/not-a-real-link", "", nil)
	require.Equal(t, http.StatusNotFound, status)

	// A weak password does not use the link up.
	status, _, _ = srv.do(t, http.MethodPost, "/api/v1/invites/"+openToken+"/accept", "", map[string]any{"email": "dev@example.com", "password": "short"})
	require.Equal(t, http.StatusBadRequest, status)

	// The teammate joins, signed in, with no registration.
	status, _, raw = srv.do(t, http.MethodPost, "/api/v1/invites/"+openToken+"/accept", "", map[string]any{
		"email": "dev@example.com", "password": "correct-horse-battery", "display_name": "Dev",
	})
	require.Equal(t, http.StatusCreated, status, string(raw))
	dev := decodeInvite(t, raw)
	require.NotEmpty(t, dev.Token)
	require.Equal(t, "payments", dev.ProjectSlug)
	require.Equal(t, "member", dev.Role)

	status, _, raw = srv.do(t, http.MethodGet, "/api/v1/projects/payments", dev.Token, nil)
	require.Equal(t, http.StatusOK, status, string(raw))
	require.Contains(t, string(raw), `"role":"member"`)

	// The link is single use, and a member cannot make links.
	status, _, _ = srv.do(t, http.MethodGet, "/api/v1/invites/"+openToken, "", nil)
	require.Equal(t, http.StatusNotFound, status)
	status, _, _ = srv.do(t, http.MethodPost, "/api/v1/invites/"+openToken+"/accept", "", map[string]any{"email": "late@example.com", "password": "correct-horse-battery"})
	require.Equal(t, http.StatusNotFound, status)
	status, _, _ = srv.do(t, http.MethodPost, "/api/v1/projects/payments/invites", dev.Token, map[string]any{"role": "member"})
	require.Equal(t, http.StatusForbidden, status)
	status, _, _ = srv.do(t, http.MethodGet, "/api/v1/projects/payments/invites", dev.Token, nil)
	require.Equal(t, http.StatusForbidden, status)

	// An invite bound to an address: another address is refused, the right
	// one (any letter case) works, and an address that already has an account
	// gets the same answer as any other failure.
	status, _, raw = srv.do(t, http.MethodPost, "/api/v1/projects/payments/invites", adminTok, map[string]any{"role": "manager", "email": "lead@example.com"})
	require.Equal(t, http.StatusCreated, status, string(raw))
	boundToken := strings.TrimPrefix(decodeInvite(t, raw).Link, "/invite/")
	status, _, raw = srv.do(t, http.MethodPost, "/api/v1/invites/"+boundToken+"/accept", "", map[string]any{"email": "intruder@example.com", "password": "correct-horse-battery"})
	require.Equal(t, http.StatusForbidden, status, string(raw))
	require.Contains(t, string(raw), "invite_email_mismatch")
	status, _, raw = srv.do(t, http.MethodPost, "/api/v1/invites/"+boundToken+"/accept", "", map[string]any{"email": "Lead@Example.com", "password": "correct-horse-battery"})
	require.Equal(t, http.StatusCreated, status, string(raw))
	require.Equal(t, "manager", decodeInvite(t, raw).Role)

	// A signed-in person joins with their own account, and an existing
	// address cannot be claimed through an invite.
	status, _, raw = srv.do(t, http.MethodPost, "/api/v1/projects", adminTok, map[string]any{"name": "Billing", "slug": "billing"})
	require.Equal(t, http.StatusCreated, status, string(raw))
	status, _, raw = srv.do(t, http.MethodPost, "/api/v1/projects/billing/invites", adminTok, map[string]any{"role": "member"})
	require.Equal(t, http.StatusCreated, status, string(raw))
	joinToken := strings.TrimPrefix(decodeInvite(t, raw).Link, "/invite/")
	status, _, raw = srv.do(t, http.MethodPost, "/api/v1/invites/"+joinToken+"/accept", "", map[string]any{"email": "dev@example.com", "password": "correct-horse-battery"})
	require.Equal(t, http.StatusUnprocessableEntity, status, string(raw))
	require.Contains(t, string(raw), "registration_failed")
	status, _, raw = srv.do(t, http.MethodPost, "/api/v1/invites/"+joinToken+"/join", dev.Token, nil)
	require.Equal(t, http.StatusOK, status, string(raw))
	status, _, _ = srv.do(t, http.MethodGet, "/api/v1/projects/billing", dev.Token, nil)
	require.Equal(t, http.StatusOK, status)
	status, _, _ = srv.do(t, http.MethodPost, "/api/v1/invites/"+joinToken+"/join", dev.Token, nil)
	require.Equal(t, http.StatusNotFound, status, "a used link is dead for joins too")

	// Revoking kills a link.
	status, _, raw = srv.do(t, http.MethodPost, "/api/v1/projects/billing/invites", adminTok, map[string]any{"role": "member"})
	require.Equal(t, http.StatusCreated, status, string(raw))
	doomed := decodeInvite(t, raw)
	status, _, _ = srv.do(t, http.MethodDelete, "/api/v1/projects/billing/invites/"+doomed.ID, adminTok, nil)
	require.Equal(t, http.StatusNoContent, status)
	status, _, _ = srv.do(t, http.MethodGet, "/api/v1/invites/"+strings.TrimPrefix(doomed.Link, "/invite/"), "", nil)
	require.Equal(t, http.StatusNotFound, status)
	status, _, _ = srv.do(t, http.MethodDelete, "/api/v1/projects/billing/invites/"+doomed.ID, adminTok, nil)
	require.Equal(t, http.StatusNotFound, status)
}
