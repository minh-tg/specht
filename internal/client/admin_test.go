package client

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// call is what a test server saw.
type call struct {
	method, path, query string
	body                map[string]any
}

// serve answers every request with status and body and records what it saw.
func serve(t *testing.T, status int, body string) (*Client, *call) {
	t.Helper()
	seen := &call{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.method, seen.path, seen.query = r.Method, r.URL.Path, r.URL.RawQuery
		raw, _ := io.ReadAll(r.Body)
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &seen.body)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return New(srv.URL, WithToken("k")), seen
}

func TestUpdateProjectSendsOnlyWhatIsGiven(t *testing.T) {
	cl, seen := serve(t, 200, `{"slug":"demo","name":"Renamed"}`)
	name := "Renamed"

	p, err := cl.UpdateProject("demo", &name, nil)

	require.NoError(t, err)
	assert.Equal(t, "PUT", seen.method)
	assert.Equal(t, "/api/v1/projects/demo", seen.path)
	assert.Equal(t, map[string]any{"name": "Renamed"}, seen.body, "an omitted description stays unchanged")
	assert.Equal(t, "Renamed", p.Name)
}

func TestUpdateProjectCanClearTheDescription(t *testing.T) {
	cl, seen := serve(t, 200, `{"slug":"demo"}`)
	empty := ""

	_, err := cl.UpdateProject("demo", nil, &empty)

	require.NoError(t, err)
	assert.Equal(t, map[string]any{"description": ""}, seen.body)
}

func TestDeleteProjectReturnsTheDeletedProject(t *testing.T) {
	cl, seen := serve(t, 200, `{"slug":"demo","name":"Demo"}`)

	p, err := cl.DeleteProject("demo")

	require.NoError(t, err)
	assert.Equal(t, "DELETE", seen.method)
	assert.Equal(t, "/api/v1/projects/demo", seen.path)
	assert.Equal(t, "Demo", p.Name)
}

func TestAddProjectMemberByEmailSendsTheAddressAndNoUserID(t *testing.T) {
	cl, seen := serve(t, 201, `{"project_id":"p1","user_id":"u1","role":"member","email":"ada@example.com","display_name":"Ada"}`)

	m, err := cl.AddProjectMemberByEmail("demo", "ada@example.com", "member")

	require.NoError(t, err)
	assert.Equal(t, "POST", seen.method)
	assert.Equal(t, "/api/v1/projects/demo/members", seen.path)
	assert.Equal(t, map[string]any{"email": "ada@example.com", "role": "member"}, seen.body, "exactly one of user_id and email")
	assert.Equal(t, "ada@example.com", m.Email)
	assert.Equal(t, "Ada", m.DisplayName)
}

func TestListUsersFiltersByEmailAndPages(t *testing.T) {
	cl, seen := serve(t, 200, `[{"id":"u1","email":"ada@example.com","role":"admin","disabled":false}]`)

	users, err := cl.ListUsers("ada", 10, 20)

	require.NoError(t, err)
	assert.Equal(t, "GET", seen.method)
	assert.Equal(t, "/api/v1/users", seen.path)
	assert.Equal(t, "email=ada&limit=10&offset=20", seen.query)
	require.Len(t, users, 1)
	assert.Equal(t, "ada@example.com", users[0].Email)
}

func TestListUsersWithoutFiltersAsksForNothingExtra(t *testing.T) {
	cl, seen := serve(t, 200, `[]`)
	_, err := cl.ListUsers("", 0, 0)
	require.NoError(t, err)
	assert.Empty(t, seen.query)
}

func TestChangeUserRole(t *testing.T) {
	cl, seen := serve(t, 200, `{"id":"u1","email":"ada@example.com","role":"admin","disabled":false}`)

	u, err := cl.ChangeUserRole("u1", "admin")

	require.NoError(t, err)
	assert.Equal(t, "PUT", seen.method)
	assert.Equal(t, "/api/v1/users/u1/role", seen.path)
	assert.Equal(t, map[string]any{"role": "admin"}, seen.body)
	assert.Equal(t, "admin", u.Role)
}

func TestPasswordResetLinkAndAccountSwitches(t *testing.T) {
	cl, seen := serve(t, 200, `{"link":"/reset/abc","expires_at":"2026-10-16T10:00:00Z"}`)
	link, err := cl.CreatePasswordResetLink("u1")
	require.NoError(t, err)
	assert.Equal(t, "POST", seen.method)
	assert.Equal(t, "/api/v1/users/u1/reset-link", seen.path)
	assert.Equal(t, "/reset/abc", link.Link)
	assert.Equal(t, "2026-10-16T10:00:00Z", link.ExpiresAt)

	cl, seen = serve(t, 200, `{"id":"u1","email":"a@b.c","role":"member","disabled":true}`)
	u, err := cl.DeactivateUser("u1", false)
	require.NoError(t, err)
	assert.Equal(t, "/api/v1/users/u1/deactivate", seen.path)
	assert.True(t, u.Disabled)
	assert.Nil(t, seen.body, "no confirmation is sent unless asked for")

	cl, seen = serve(t, 200, `{"id":"u1","email":"a@b.c","role":"member","disabled":true}`)
	_, err = cl.DeactivateUser("u1", true)
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"force": true}, seen.body)

	cl, seen = serve(t, 200, `{"id":"u1","email":"a@b.c","role":"member","disabled":false}`)
	u, err = cl.ReactivateUser("u1")
	require.NoError(t, err)
	assert.Equal(t, "/api/v1/users/u1/reactivate", seen.path)
	assert.False(t, u.Disabled)
}

func TestInvites(t *testing.T) {
	cl, seen := serve(t, 200, `[{"id":"i1","role":"member","email":"new@example.com","created_by":"boss@example.com","created_at":"2026-10-01T10:00:00Z","expires_at":"2026-10-08T10:00:00Z"}]`)
	invites, err := cl.ListInvites("demo")
	require.NoError(t, err)
	assert.Equal(t, "GET", seen.method)
	assert.Equal(t, "/api/v1/projects/demo/invites", seen.path)
	require.Len(t, invites, 1)
	assert.Equal(t, "new@example.com", invites[0].Email)

	cl, seen = serve(t, 201, `{"id":"i2","role":"manager","created_at":"","expires_at":"2026-10-08T10:00:00Z","link":"/invite/tok"}`)
	inv, err := cl.CreateInvite("demo", "manager", "", 3)
	require.NoError(t, err)
	assert.Equal(t, "POST", seen.method)
	assert.Equal(t, map[string]any{"role": "manager", "expires_in_days": float64(3)}, seen.body, "an empty address is not sent")
	assert.Equal(t, "/invite/tok", inv.Link)

	cl, seen = serve(t, 201, `{"id":"i3","role":"member","created_at":"","expires_at":"","link":"/invite/t2"}`)
	_, err = cl.CreateInvite("demo", "member", "new@example.com", 0)
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"role": "member", "email": "new@example.com"}, seen.body, "zero days leaves the server's default")

	cl, seen = serve(t, 204, ``)
	require.NoError(t, cl.RevokeInvite("demo", "i1"))
	assert.Equal(t, "DELETE", seen.method)
	assert.Equal(t, "/api/v1/projects/demo/invites/i1", seen.path)
}
