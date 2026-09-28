//go:build e2e

package e2e

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Local shapes for the profile and API key endpoints.

type profileEnvelope struct {
	ID          string  `json:"id"`
	Email       string  `json:"email"`
	DisplayName *string `json:"display_name"`
	Role        string  `json:"role"`
	CreatedAt   string  `json:"created_at"`
}

type apiKeyEnvelope struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	KeyPrefix string  `json:"key_prefix"`
	RawKey    string  `json:"raw_key"` // only present in the creation response
	LastFour  *string `json:"last_four"`
	CreatedAt string  `json:"created_at"`
}

// TestE2E_ProfileUpdate covers the profile process: a signed-in user
// edits their own
// profile — trimming, persistence, clearing — and API keys are refused on
// the session-only routes.
func TestE2E_ProfileUpdate(t *testing.T) {
	viewerToken := login(t, "e2e-viewer@example.com", adminPass)

	me := request[profileEnvelope](t, http.MethodGet, "/api/v1/me", viewerToken, nil, http.StatusOK)

	t.Run("display name round-trips with trimming and persistence", func(t *testing.T) {
		set := request[profileEnvelope](t, http.MethodPut, "/api/v1/me", viewerToken,
			map[string]string{"display_name": "  Ada Lovelace  "}, http.StatusOK)
		require.NotNil(t, set.DisplayName)
		require.Equal(t, "Ada Lovelace", *set.DisplayName, "surrounding whitespace is trimmed")

		got := request[profileEnvelope](t, http.MethodGet, "/api/v1/me", viewerToken, nil, http.StatusOK)
		require.NotNil(t, got.DisplayName)
		require.Equal(t, "Ada Lovelace", *got.DisplayName)
		require.Equal(t, me.ID, got.ID, "the update does not change identity")
	})

	t.Run("blank or absent display name clears it", func(t *testing.T) {
		cleared := request[profileEnvelope](t, http.MethodPut, "/api/v1/me", viewerToken,
			map[string]string{"display_name": "   "}, http.StatusOK)
		require.Nil(t, cleared.DisplayName, "a blank name clears the field (documented)")
		got := request[profileEnvelope](t, http.MethodGet, "/api/v1/me", viewerToken, nil, http.StatusOK)
		require.Nil(t, got.DisplayName)

		// Omitting the key entirely also clears it: nil or blank clears.
		request[profileEnvelope](t, http.MethodPut, "/api/v1/me", viewerToken,
			map[string]string{"display_name": "temp"}, http.StatusOK)
		blank := request[profileEnvelope](t, http.MethodPut, "/api/v1/me", viewerToken,
			map[string]any{}, http.StatusOK)
		require.Nil(t, blank.DisplayName)
	})

	t.Run("profile routes are session-only", func(t *testing.T) {
		slug := newProject(t, "me-key")
		key := mintKey(t, slug)

		status, raw := doJSON(t, http.MethodGet, "/api/v1/me", key, nil)
		require.Equal(t, http.StatusForbidden, status, string(raw))
		require.Equal(t, "insufficient_role", errorCode(t, raw))

		status, raw = doJSON(t, http.MethodPut, "/api/v1/me", key,
			map[string]string{"display_name": "service"})
		require.Equal(t, http.StatusForbidden, status, string(raw))
		require.Equal(t, "insufficient_role", errorCode(t, raw))
	})
}

// TestE2E_APIKeyLifecycle covers the API key lifecycle end to end:
// creation validates input
// and returns the one-time secret, list and revoke operate over the real
// store, revoked and expired keys stop authenticating, and the role/scope
// gates hold on every route.
func TestE2E_APIKeyLifecycle(t *testing.T) {
	slug := newProject(t, "api-keys")
	viewerToken := login(t, "e2e-viewer@example.com", adminPass)
	gatePath := "/api/v1/projects/" + slug + "/gate"

	listKeys := func(t *testing.T) []apiKeyEnvelope {
		return request[[]apiKeyEnvelope](t, http.MethodGet,
			"/api/v1/auth/apikeys?project="+slug, adminToken, nil, http.StatusOK)
	}

	t.Run("creation validates input and returns the one-time secret", func(t *testing.T) {
		status, raw := doJSON(t, http.MethodPost, "/api/v1/auth/apikeys", adminToken,
			map[string]any{"project": slug})
		require.Equal(t, http.StatusBadRequest, status, string(raw))
		require.Equal(t, "missing_field", errorCode(t, raw))

		status, raw = doJSON(t, http.MethodPost, "/api/v1/auth/apikeys", adminToken,
			map[string]any{"project": slug, "name": "bad-expiry", "expires_at": "yesterday"})
		require.Equal(t, http.StatusBadRequest, status, string(raw))
		require.Equal(t, "invalid_expires_at", errorCode(t, raw))

		status, raw = doJSON(t, http.MethodPost, "/api/v1/auth/apikeys", viewerToken,
			map[string]any{"project": slug, "name": "viewer-key"})
		require.Equal(t, http.StatusForbidden, status, string(raw))
		require.Equal(t, "insufficient_role", errorCode(t, raw), "creating keys is admin-only")

		created := request[apiKeyEnvelope](t, http.MethodPost, "/api/v1/auth/apikeys", adminToken,
			map[string]any{"project": slug, "name": "e2e-main"}, http.StatusCreated)
		require.NotEmpty(t, created.ID)
		require.Equal(t, "e2e-main", created.Name)
		require.NotEmpty(t, created.KeyPrefix)
		require.True(t, len(created.RawKey) > 4)
		require.NotNil(t, created.LastFour)
		require.Equal(t, created.RawKey[len(created.RawKey)-4:], *created.LastFour)
		require.NotEmpty(t, created.CreatedAt)
	})

	t.Run("keys work until revoked or expired", func(t *testing.T) {
		future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
		active := request[apiKeyEnvelope](t, http.MethodPost, "/api/v1/auth/apikeys", adminToken,
			map[string]any{"project": slug, "name": "active", "expires_at": future}, http.StatusCreated)
		past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
		expired := request[apiKeyEnvelope](t, http.MethodPost, "/api/v1/auth/apikeys", adminToken,
			map[string]any{"project": slug, "name": "expired", "expires_at": past}, http.StatusCreated)

		// The active key authenticates: it can read the merge gate.
		status, raw := doJSON(t, http.MethodGet, gatePath, active.RawKey, nil)
		require.Equal(t, http.StatusOK, status, string(raw))

		// A key born expired never authenticates, though creation succeeded.
		status, raw = doJSON(t, http.MethodGet, gatePath, expired.RawKey, nil)
		require.Equal(t, http.StatusUnauthorized, status, string(raw))
		require.Equal(t, "invalid_token", errorCode(t, raw))

		// Find the active key's id in the listing, then revoke it.
		var activeID string
		for _, k := range listKeys(t) {
			if k.Name == "active" {
				activeID = k.ID
			}
			require.Empty(t, k.RawKey, "listing never echoes a raw key")
		}
		require.NotEmpty(t, activeID)
		status, raw = doJSON(t, http.MethodDelete, "/api/v1/auth/apikeys/"+activeID+"?project="+slug,
			adminToken, nil)
		require.Equal(t, http.StatusNoContent, status, string(raw))

		status, raw = doJSON(t, http.MethodGet, gatePath, active.RawKey, nil)
		require.Equal(t, http.StatusUnauthorized, status, string(raw))
		require.Equal(t, "invalid_token", errorCode(t, raw),
			"a revoked key stops authenticating")

		for _, k := range listKeys(t) {
			require.NotEqual(t, "active", k.Name, "revoked keys leave the listing")
		}
	})

	t.Run("revocation rejects malformed, missing, and unauthorized requests", func(t *testing.T) {
		status, raw := doJSON(t, http.MethodDelete,
			"/api/v1/auth/apikeys/not-a-uuid?project="+slug, adminToken, nil)
		require.Equal(t, http.StatusBadRequest, status, string(raw))
		require.Equal(t, "invalid_id", errorCode(t, raw),
			"malformed key id is a client error, not a 500")

		unknown := randomHex(16)
		status, raw = doJSON(t, http.MethodDelete,
			"/api/v1/auth/apikeys/"+unknown+"?project="+slug, adminToken, nil)
		require.Equal(t, http.StatusNotFound, status, string(raw))
		require.Equal(t, "not_found", errorCode(t, raw),
			"unknown key id is a 404, not a generic 422")

		status, raw = doJSON(t, http.MethodDelete, "/api/v1/auth/apikeys/"+unknown, adminToken, nil)
		require.Equal(t, http.StatusBadRequest, status, string(raw))
		require.Equal(t, "missing_field", errorCode(t, raw))

		status, raw = doJSON(t, http.MethodGet, "/api/v1/auth/apikeys", adminToken, nil)
		require.Equal(t, http.StatusBadRequest, status, string(raw))
		require.Equal(t, "missing_field", errorCode(t, raw))

		status, raw = doJSON(t, http.MethodGet,
			"/api/v1/auth/apikeys?project=no-such-project", adminToken, nil)
		require.Equal(t, http.StatusNotFound, status, string(raw))
		require.Equal(t, "not_found", errorCode(t, raw))

		status, raw = doJSON(t, http.MethodDelete,
			"/api/v1/auth/apikeys/"+unknown+"?project="+slug, viewerToken, nil)
		require.Equal(t, http.StatusForbidden, status, string(raw))
		require.Equal(t, "insufficient_role", errorCode(t, raw))

		status, raw = doJSON(t, http.MethodDelete,
			"/api/v1/auth/apikeys/"+unknown+"?project="+slug, mintKey(t, slug), nil)
		require.Equal(t, http.StatusForbidden, status, string(raw))
		require.Equal(t, "insufficient_scope", errorCode(t, raw),
			"admin commands are never key-scoped")
	})
}

// TestE2E_UserDirectory covers the account directory the admin surfaces pick
// a user from: an admin lists accounts, narrows by an email substring, and
// pages through them. It is session-admin only — a project key must never
// enumerate the organization — and it never returns credential material.
func TestE2E_UserDirectory(t *testing.T) {
	viewer := login(t, "e2e-viewer@example.com", adminPass)
	viewerProfile := request[profileEnvelope](t, http.MethodGet, "/api/v1/me", viewer, nil, http.StatusOK)
	slug := newProject(t, "user-directory")

	t.Run("an admin lists accounts ordered by email", func(t *testing.T) {
		users := request[[]profileEnvelope](t, http.MethodGet, "/api/v1/users", adminToken, nil, http.StatusOK)
		require.GreaterOrEqual(t, len(users), 2, "the harness registers an admin and a viewer")

		var emails []string
		for _, u := range users {
			emails = append(emails, u.Email)
			require.NotEmpty(t, u.ID)
			require.NotEmpty(t, u.Role)
			require.NotEmpty(t, u.CreatedAt)
		}
		require.Contains(t, emails, viewerProfile.Email)
		require.IsIncreasing(t, emails, "the directory is ordered by email so pages are stable")
	})

	t.Run("the email filter narrows the directory", func(t *testing.T) {
		exact := request[[]profileEnvelope](t, http.MethodGet,
			"/api/v1/users?email="+viewerProfile.Email, adminToken, nil, http.StatusOK)
		require.Len(t, exact, 1)
		require.Equal(t, viewerProfile.ID, exact[0].ID)

		partial := request[[]profileEnvelope](t, http.MethodGet,
			"/api/v1/users?email=VIEWER", adminToken, nil, http.StatusOK)
		require.Len(t, partial, 1, "the filter matches a case-insensitive substring")
		require.Equal(t, viewerProfile.ID, partial[0].ID)

		require.Empty(t, request[[]profileEnvelope](t, http.MethodGet,
			"/api/v1/users?email=nobody-matches-this", adminToken, nil, http.StatusOK))
	})

	t.Run("limit and offset bound the page", func(t *testing.T) {
		all := request[[]profileEnvelope](t, http.MethodGet, "/api/v1/users", adminToken, nil, http.StatusOK)

		first := request[[]profileEnvelope](t, http.MethodGet,
			"/api/v1/users?limit=1", adminToken, nil, http.StatusOK)
		require.Len(t, first, 1)
		require.Equal(t, all[0].ID, first[0].ID, "the first page starts at the first account")

		second := request[[]profileEnvelope](t, http.MethodGet,
			"/api/v1/users?limit=1&offset=1", adminToken, nil, http.StatusOK)
		require.Len(t, second, 1)
		require.Equal(t, all[1].ID, second[0].ID, "offset moves the window")

		require.Empty(t, request[[]profileEnvelope](t, http.MethodGet,
			"/api/v1/users?offset=1000", adminToken, nil, http.StatusOK))
		require.Len(t, request[[]profileEnvelope](t, http.MethodGet,
			"/api/v1/users?limit=-1", adminToken, nil, http.StatusOK), len(all),
			"a negative limit falls back to the default page rather than erroring")
	})

	t.Run("only an admin session may enumerate accounts", func(t *testing.T) {
		status, raw := doJSON(t, http.MethodGet, "/api/v1/users", viewer, nil)
		require.Equal(t, http.StatusForbidden, status, string(raw))
		require.Equal(t, "insufficient_role", errorCode(t, raw))

		status, raw = doJSON(t, http.MethodGet, "/api/v1/users", mintKey(t, slug), nil)
		require.Equal(t, http.StatusForbidden, status, string(raw))
		require.Equal(t, "insufficient_role", errorCode(t, raw),
			"a project key has no business enumerating the organization")

		status, raw = doJSON(t, http.MethodGet, "/api/v1/users", "", nil)
		require.Equal(t, http.StatusUnauthorized, status, string(raw))
		require.Equal(t, "missing_token", errorCode(t, raw))
	})

	t.Run("the directory never returns credential material", func(t *testing.T) {
		status, raw := doJSON(t, http.MethodGet, "/api/v1/users", adminToken, nil)
		require.Equal(t, http.StatusOK, status)
		require.NotContains(t, string(raw), "password")
		require.NotContains(t, string(raw), "hash")
	})
}
