//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type memberSuggestion struct {
	UserID      string `json:"user_id"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
}

// suggestionsServer is a private server with sign-up closed, the only state in
// which the endpoint suggests anyone. The shared server runs with sign-up open.
type suggestionsServer struct {
	*freshServer
	root string // the first admin's session
}

func startSuggestionsServer(t *testing.T) *suggestionsServer {
	t.Helper()
	srv := startFreshServer(t, "specht_member_suggest_"+randomHex(3))
	match := setupTokenInLog.FindStringSubmatch(srv.readLog())
	require.Len(t, match, 2, "setup token is logged at startup:\n%s", srv.readLog())
	status, _, raw := srv.do(t, http.MethodPost, "/api/v1/setup", "", map[string]any{
		"token": strings.Trim(match[1], `"`), "email": "root@example.com",
		"password": "correct-horse-battery", "display_name": "Root",
	})
	require.Equal(t, http.StatusCreated, status, string(raw))
	var session authResponse
	require.NoError(t, json.Unmarshal(raw, &session))
	return &suggestionsServer{freshServer: srv, root: session.Token}
}

func (s *suggestionsServer) project(t *testing.T, slug string) {
	t.Helper()
	status, _, raw := s.do(t, http.MethodPost, "/api/v1/projects", s.root, map[string]string{"name": slug, "slug": slug})
	require.Equal(t, http.StatusCreated, status, string(raw))
}

// invite creates an account through an invite link to lobby, the way people
// join while sign-up is closed, and returns its session.
func (s *suggestionsServer) invite(t *testing.T, email, displayName string) string {
	t.Helper()
	status, _, raw := s.do(t, http.MethodPost, "/api/v1/projects/lobby/invites", s.root, map[string]any{"role": "member", "email": email})
	require.Equal(t, http.StatusCreated, status, string(raw))
	var inv struct {
		Link string `json:"link"`
	}
	require.NoError(t, json.Unmarshal(raw, &inv))
	token := inv.Link[strings.LastIndex(inv.Link, "/")+1:]
	body := map[string]any{"email": email, "password": "correct-horse-battery"}
	if displayName != "" {
		body["display_name"] = displayName
	}
	status, _, raw = s.do(t, http.MethodPost, "/api/v1/invites/"+token+"/accept", "", body)
	require.Equal(t, http.StatusCreated, status, string(raw))
	var session authResponse
	require.NoError(t, json.Unmarshal(raw, &session))
	return session.Token
}

func (s *suggestionsServer) grant(t *testing.T, slug, email, role string) {
	t.Helper()
	status, _, raw := s.do(t, http.MethodPost, "/api/v1/projects/"+slug+"/members", s.root, map[string]string{"email": email, "role": role})
	require.Equal(t, http.StatusCreated, status, string(raw))
}

// manager returns the session of a new manager of slug. Each check uses its own,
// so the per-person rate limit never decides an unrelated check.
func (s *suggestionsServer) manager(t *testing.T, slug string) string {
	t.Helper()
	email := "mgr-" + randomHex(3) + "@acme.example"
	token := s.invite(t, email, "")
	s.grant(t, slug, email, "manager")
	return token
}

func (s *suggestionsServer) suggest(t *testing.T, token, slug, q string) (int, []byte) {
	t.Helper()
	status, _, raw := s.do(t, http.MethodGet, "/api/v1/projects/"+slug+"/member-suggestions?q="+url.QueryEscape(q), token, nil)
	return status, raw
}

func (s *suggestionsServer) suggestedEmails(t *testing.T, token, slug, q string) []string {
	t.Helper()
	status, raw := s.suggest(t, token, slug, q)
	require.Equal(t, http.StatusOK, status, string(raw))
	var got []memberSuggestion
	require.NoError(t, json.Unmarshal(raw, &got), string(raw))
	require.NotNil(t, got, "no suggestions is [], not null: %s", raw)
	emails := make([]string, len(got))
	for i, p := range got {
		emails[i] = p.Email
	}
	return emails
}

// TestE2E_MemberSuggestions drives the Add Direct Member autocomplete against a
// real server and database with sign-up closed.
func TestE2E_MemberSuggestions(t *testing.T) {
	s := startSuggestionsServer(t)
	s.project(t, "lobby")
	s.project(t, "target")

	plain := s.invite(t, "plain@acme.example", "")
	s.grant(t, "target", "plain@acme.example", "member")
	s.invite(t, "ada@acme.example", "Ada Lovelace")
	s.invite(t, "adam@acme.example", "")
	s.invite(t, "a_b@acme.example", "")
	s.invite(t, "axb@acme.example", "")

	t.Run("a project manager finds people by email prefix and display-name word", func(t *testing.T) {
		manager := s.manager(t, "target")
		require.Equal(t, []string{"ada@acme.example", "adam@acme.example"}, s.suggestedEmails(t, manager, "target", "ADA"))
		require.Equal(t, []string{"ada@acme.example"}, s.suggestedEmails(t, manager, "target", "love"))
		require.Empty(t, s.suggestedEmails(t, manager, "target", "acme"), "a match inside the email is not a prefix")

		status, raw := s.suggest(t, manager, "target", "ada")
		require.Equal(t, http.StatusOK, status)
		var got []memberSuggestion
		require.NoError(t, json.Unmarshal(raw, &got))
		require.Equal(t, "Ada Lovelace", got[0].DisplayName)
		require.NotEmpty(t, got[0].UserID)
	})

	t.Run("the instance admin may ask too", func(t *testing.T) {
		require.Equal(t, []string{"ada@acme.example", "adam@acme.example"}, s.suggestedEmails(t, s.root, "target", "ada"))
	})

	t.Run("a plain member and a project API key are refused", func(t *testing.T) {
		status, raw := s.suggest(t, plain, "target", "ada")
		require.Equal(t, http.StatusForbidden, status, string(raw))

		status, _, raw = s.do(t, http.MethodPost, "/api/v1/auth/apikeys", s.root, map[string]string{"project": "target", "name": "ci"})
		require.Equal(t, http.StatusCreated, status, string(raw))
		var key apiKeyResponse
		require.NoError(t, json.Unmarshal(raw, &key))
		status, raw = s.suggest(t, key.RawKey, "target", "ada")
		require.Equal(t, http.StatusForbidden, status, string(raw))
	})

	t.Run("a missing project answers like the add-member route", func(t *testing.T) {
		manager := s.manager(t, "target")
		status, raw := s.suggest(t, manager, "no-such-project", "ada")
		require.Equal(t, http.StatusForbidden, status, string(raw))
		status, raw = s.suggest(t, s.root, "no-such-project", "ada")
		require.Equal(t, http.StatusNotFound, status, string(raw))
	})

	t.Run("% and _ match only themselves", func(t *testing.T) {
		manager := s.manager(t, "target")
		require.Equal(t, []string{"a_b@acme.example"}, s.suggestedEmails(t, manager, "target", "a_b"))
		require.Empty(t, s.suggestedEmails(t, manager, "target", "%%%"))
		require.Empty(t, s.suggestedEmails(t, manager, "target", "___"))
	})

	t.Run("fewer than three characters returns an empty list and over 64 is refused", func(t *testing.T) {
		manager := s.manager(t, "target")
		require.Empty(t, s.suggestedEmails(t, manager, "target", "ad"))
		require.Empty(t, s.suggestedEmails(t, manager, "target", "  ad  "))
		status, raw := s.suggest(t, manager, "target", strings.Repeat("a", 65))
		require.Equal(t, http.StatusBadRequest, status, string(raw))
	})

	t.Run("an added member is no longer suggested", func(t *testing.T) {
		manager := s.manager(t, "target")
		s.grant(t, "target", "ada@acme.example", "member")
		require.Equal(t, []string{"adam@acme.example"}, s.suggestedEmails(t, manager, "target", "ada"))
		require.Empty(t, s.suggestedEmails(t, manager, "target", "plain"), "a member of the project is not offered")
		s.project(t, "elsewhere")
		require.Equal(t, []string{"ada@acme.example"}, s.suggestedEmails(t, s.root, "elsewhere", "love"),
			"membership of one project does not hide a person from another")
	})

	t.Run("one person over the rate limit gets 429 while others carry on", func(t *testing.T) {
		busy := s.manager(t, "target")
		other := s.manager(t, "target")
		limited := 0
		for range 15 {
			status, _ := s.suggest(t, busy, "target", "ada")
			if status == http.StatusTooManyRequests {
				limited++
			} else {
				require.Equal(t, http.StatusOK, status)
			}
		}
		require.Positive(t, limited, "15 quick requests exceed a burst of 10")
		require.Equal(t, []string{"adam@acme.example"}, s.suggestedEmails(t, other, "target", "ada"))
	})
}

// TestE2E_MemberSuggestionsEmptyWithOpenRegistration uses the shared server,
// where anyone can sign up, so nobody is ever suggested.
func TestE2E_MemberSuggestionsEmptyWithOpenRegistration(t *testing.T) {
	slug := newProject(t, "suggest-open")
	registerPerson(t, "suggestable")

	status, raw := doJSON(t, http.MethodGet, "/api/v1/projects/"+slug+"/member-suggestions?q=suggestable", adminToken, nil)
	require.Equal(t, http.StatusOK, status, string(raw))
	require.JSONEq(t, `[]`, string(raw))
}
