//go:build e2e

package e2e

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const inviteTestPassword = "correct-horse-battery"

type inviteStack struct {
	srv      *freshServer
	adminTok string
}

func bootInviteStack(t *testing.T, dbName string) *inviteStack {
	t.Helper()
	const setupToken = "invite-authority-setup-token-01"
	srv := startFreshServer(t, dbName, "SETUP_TOKEN="+setupToken, "REGISTRATION_ENABLED=false")
	status, _, raw := srv.do(t, http.MethodPost, "/api/v1/setup", "", map[string]any{
		"token": setupToken, "email": "root@example.com", "password": inviteTestPassword,
	})
	require.Equal(t, http.StatusCreated, status, string(raw))
	return &inviteStack{srv: srv, adminTok: decodeInvite(t, raw).Token}
}

func (s *inviteStack) userID(t *testing.T, token string) string {
	t.Helper()
	status, _, raw := s.srv.do(t, http.MethodGet, "/api/v1/me", token, nil)
	require.Equal(t, http.StatusOK, status, string(raw))
	return decodeInvite(t, raw).ID
}

func (s *inviteStack) project(t *testing.T, slug string) {
	t.Helper()
	status, _, raw := s.srv.do(t, http.MethodPost, "/api/v1/projects", s.adminTok, map[string]any{"name": slug, "slug": slug})
	require.Equal(t, http.StatusCreated, status, string(raw))
}

// mint creates an invite as the given caller and returns its bare token.
func (s *inviteStack) mint(t *testing.T, callerTok, slug, role string) string {
	t.Helper()
	status, _, raw := s.srv.do(t, http.MethodPost, "/api/v1/projects/"+slug+"/invites", callerTok, map[string]any{"role": role})
	require.Equal(t, http.StatusCreated, status, string(raw))
	return strings.TrimPrefix(decodeInvite(t, raw).Link, "/invite/")
}

// account creates a person on the project through an invite the admin made.
func (s *inviteStack) account(t *testing.T, slug, role, email string) (token, id string) {
	t.Helper()
	link := s.mint(t, s.adminTok, slug, role)
	status, _, raw := s.srv.do(t, http.MethodPost, "/api/v1/invites/"+link+"/accept", "", map[string]any{
		"email": email, "password": inviteTestPassword,
	})
	require.Equal(t, http.StatusCreated, status, string(raw))
	token = decodeInvite(t, raw).Token
	return token, s.userID(t, token)
}

func (s *inviteStack) setMemberRole(t *testing.T, slug, userID, role string) {
	t.Helper()
	status, _, raw := s.srv.do(t, http.MethodPost, "/api/v1/projects/"+slug+"/members", s.adminTok, map[string]any{"user_id": userID, "role": role})
	require.Equal(t, http.StatusCreated, status, string(raw))
}

func (s *inviteStack) projectRole(t *testing.T, token, slug string) (int, string) {
	t.Helper()
	status, _, raw := s.srv.do(t, http.MethodGet, "/api/v1/projects/"+slug, token, nil)
	if status != http.StatusOK {
		return status, ""
	}
	for _, role := range []string{"admin", "manager", "member"} {
		if strings.Contains(string(raw), `"role":"`+role+`"`) {
			return status, role
		}
	}
	return status, "?"
}

func (s *inviteStack) accept(t *testing.T, link, email string) (int, []byte) {
	t.Helper()
	status, _, raw := s.srv.do(t, http.MethodPost, "/api/v1/invites/"+link+"/accept", "", map[string]any{
		"email": email, "password": inviteTestPassword,
	})
	return status, raw
}

func (s *inviteStack) requireDead(t *testing.T, link string) {
	t.Helper()
	status, _, raw := s.srv.do(t, http.MethodGet, "/api/v1/invites/"+link, "", nil)
	require.Equal(t, http.StatusNotFound, status, "lookup: "+string(raw))
}

// TestE2E_InviteFollowsItsCreatorsAuthority checks that a link works only
// while the person who made it could still make it: after they are
// deactivated, removed from the project, demoted, or lose global admin, the
// link answers like an expired one.
func TestE2E_InviteFollowsItsCreatorsAuthority(t *testing.T) {
	s := bootInviteStack(t, "invite_creator_authority")
	s.project(t, "payments")

	t.Run("creator deactivated", func(t *testing.T) {
		mgrTok, mgrID := s.account(t, "payments", "manager", "mgr1@example.com")
		link := s.mint(t, mgrTok, "payments", "manager")

		status, _, raw := s.srv.do(t, http.MethodPost, "/api/v1/users/"+mgrID+"/deactivate", s.adminTok, map[string]any{"force": true})
		require.Equal(t, http.StatusOK, status, string(raw))

		s.requireDead(t, link)
		status, raw = s.accept(t, link, "newcomer1@example.com")
		require.Equal(t, http.StatusNotFound, status, string(raw))
	})

	t.Run("creator removed from the project", func(t *testing.T) {
		mgrTok, mgrID := s.account(t, "payments", "manager", "mgr2@example.com")
		link := s.mint(t, mgrTok, "payments", "manager")

		status, _, raw := s.srv.do(t, http.MethodDelete, "/api/v1/projects/payments/members/"+mgrID, s.adminTok, nil)
		require.Equal(t, http.StatusNoContent, status, string(raw))

		s.requireDead(t, link)
		status, _, raw = s.srv.do(t, http.MethodPost, "/api/v1/invites/"+link+"/join", mgrTok, nil)
		require.Equal(t, http.StatusNotFound, status, string(raw))
		st, _ := s.projectRole(t, mgrTok, "payments")
		require.NotEqual(t, http.StatusOK, st, "the join gave no access back")
	})

	t.Run("creator demoted to member", func(t *testing.T) {
		mgrTok, mgrID := s.account(t, "payments", "manager", "mgr3@example.com")
		link := s.mint(t, mgrTok, "payments", "manager")
		s.setMemberRole(t, "payments", mgrID, "member")

		s.requireDead(t, link)
		status, _, raw := s.srv.do(t, http.MethodPost, "/api/v1/invites/"+link+"/join", mgrTok, nil)
		require.Equal(t, http.StatusNotFound, status, string(raw))
		_, role := s.projectRole(t, mgrTok, "payments")
		require.Equal(t, "member", role, "the join did not raise the role")
		status, raw = s.accept(t, link, "newcomer3@example.com")
		require.Equal(t, http.StatusNotFound, status, string(raw))
	})

	t.Run("creator was a global admin who was demoted", func(t *testing.T) {
		_, admID := s.account(t, "payments", "member", "adm5@example.com")
		status, _, raw := s.srv.do(t, http.MethodPut, "/api/v1/users/"+admID+"/role", s.adminTok, map[string]any{"role": "admin"})
		require.Equal(t, http.StatusOK, status, string(raw))
		status, _, raw = s.srv.do(t, http.MethodPost, "/api/v1/auth/login", "", map[string]any{"email": "adm5@example.com", "password": inviteTestPassword})
		require.Equal(t, http.StatusOK, status, string(raw))
		link := s.mint(t, decodeInvite(t, raw).Token, "payments", "manager")

		status, _, raw = s.srv.do(t, http.MethodPut, "/api/v1/users/"+admID+"/role", s.adminTok, map[string]any{"role": "member"})
		require.Equal(t, http.StatusOK, status, string(raw))

		s.requireDead(t, link)
		status, raw = s.accept(t, link, "newcomer5@example.com")
		require.Equal(t, http.StatusNotFound, status, string(raw))
	})

	t.Run("creator unchanged", func(t *testing.T) {
		mgrTok, _ := s.account(t, "payments", "manager", "mgr6@example.com")
		link := s.mint(t, mgrTok, "payments", "manager")

		status, _, raw := s.srv.do(t, http.MethodGet, "/api/v1/invites/"+link, "", nil)
		require.Equal(t, http.StatusOK, status, string(raw))
		status, raw = s.accept(t, link, "newcomer6@example.com")
		require.Equal(t, http.StatusCreated, status, string(raw))
		_, role := s.projectRole(t, decodeInvite(t, raw).Token, "payments")
		require.Equal(t, "manager", role)
	})

	t.Run("creator demoted and promoted back", func(t *testing.T) {
		mgrTok, mgrID := s.account(t, "payments", "manager", "mgr7@example.com")
		link := s.mint(t, mgrTok, "payments", "manager")

		s.setMemberRole(t, "payments", mgrID, "member")
		s.requireDead(t, link)
		s.setMemberRole(t, "payments", mgrID, "manager")

		status, _, raw := s.srv.do(t, http.MethodGet, "/api/v1/invites/"+link, "", nil)
		require.Equal(t, http.StatusOK, status, string(raw))
		status, raw = s.accept(t, link, "newcomer7@example.com")
		require.Equal(t, http.StatusCreated, status, string(raw))
		_, role := s.projectRole(t, decodeInvite(t, raw).Token, "payments")
		require.Equal(t, "manager", role)
	})
}
