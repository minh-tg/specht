//go:build e2e

package e2e

import (
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// activeDirectAdmins counts the project's direct admins who are not in the
// deactivated set.
func activeDirectAdmins(t *testing.T, slug string, deactivated map[string]bool) int {
	t.Helper()
	n := 0
	for _, m := range request[[]memberResponse](t, http.MethodGet, "/api/v1/projects/"+slug+"/members", adminToken, nil, http.StatusOK) {
		if m.Role == "admin" && !deactivated[m.UserID] {
			n++
		}
	}
	return n
}

// pacedPerson registers a person slowly enough to stay under the auth rate
// limit that wraps registration and sign-in.
func pacedPerson(t *testing.T, label string) miPerson {
	t.Helper()
	time.Sleep(150 * time.Millisecond)
	return miNewPerson(t, label)
}

// reactivateAndSignIn reactivates a person and signs them in again, since a
// deactivation ends the old session.
func reactivateAndSignIn(t *testing.T, p *miPerson) {
	t.Helper()
	status, raw := doJSON(t, http.MethodPost, "/api/v1/users/"+p.ID+"/reactivate", adminToken, nil)
	require.Equalf(t, http.StatusOK, status, "%s", raw)
	time.Sleep(150 * time.Millisecond)
	p.Token = login(t, p.Email, adminPass)
}

// projectAdministeredBy makes a project whose only direct admins are a and b.
func projectAdministeredBy(t *testing.T, label string, a, b miPerson) string {
	t.Helper()
	slug := newProject(t, "race-"+label)
	me := request[userProfile](t, http.MethodGet, "/api/v1/me", adminToken, nil, http.StatusOK)
	for _, id := range []string{a.ID, b.ID} {
		status, _ := miAddMember(t, adminToken, slug, id, "admin")
		require.Equal(t, http.StatusCreated, status)
	}
	status, _ := miRemoveMember(t, adminToken, slug, me.ID)
	require.Equal(t, http.StatusNoContent, status)
	return slug
}

// Two instance admins deactivating the two admins of one project at the same
// time must not both succeed: the sole-admin check runs under the project's
// membership lock.
func TestConcurrentDeactivationsKeepAProjectAdmin(t *testing.T) {
	const rounds = 30
	orphaned := 0
	a := pacedPerson(t, "deact-a")
	b := pacedPerson(t, "deact-b")
	for i := 0; i < rounds; i++ {
		reactivateAndSignIn(t, &a)
		reactivateAndSignIn(t, &b)
		slug := projectAdministeredBy(t, "deact", a, b)
		var wg sync.WaitGroup
		start := make(chan struct{})
		var sa, sb int
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			sa, _ = doJSON(t, http.MethodPost, "/api/v1/users/"+a.ID+"/deactivate", adminToken, nil)
		}()
		go func() {
			defer wg.Done()
			<-start
			sb, _ = doJSON(t, http.MethodPost, "/api/v1/users/"+b.ID+"/deactivate", adminToken, nil)
		}()
		close(start)
		wg.Wait()
		if sa == http.StatusOK && sb == http.StatusOK {
			require.Zero(t, activeDirectAdmins(t, slug, map[string]bool{a.ID: true, b.ID: true}))
			orphaned++
		}
	}
	require.Zero(t, orphaned, "rounds where both deactivations landed and left no active admin")
}

// A project admin removing the other admin while an instance admin deactivates
// the remover must not both succeed.
func TestMemberRemovalRacingDeactivationKeepsAProjectAdmin(t *testing.T) {
	const rounds = 30
	orphaned := 0
	a := pacedPerson(t, "rmdeact-a")
	b := pacedPerson(t, "rmdeact-b")
	for i := 0; i < rounds; i++ {
		reactivateAndSignIn(t, &a)
		reactivateAndSignIn(t, &b)
		slug := projectAdministeredBy(t, "rmdeact", a, b)
		var wg sync.WaitGroup
		start := make(chan struct{})
		var sRemove, sDeact int
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			sRemove, _ = miRemoveMember(t, a.Token, slug, b.ID)
		}()
		go func() {
			defer wg.Done()
			<-start
			sDeact, _ = doJSON(t, http.MethodPost, "/api/v1/users/"+a.ID+"/deactivate", adminToken, nil)
		}()
		close(start)
		wg.Wait()
		if sRemove == http.StatusNoContent && sDeact == http.StatusOK {
			require.Zero(t, activeDirectAdmins(t, slug, map[string]bool{a.ID: true}))
			orphaned++
		}
	}
	require.Zero(t, orphaned, "rounds where the removal and the deactivation both landed and left no active admin")
}
