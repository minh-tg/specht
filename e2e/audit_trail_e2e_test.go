//go:build e2e

package e2e

import (
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func auditLines(t *testing.T, event string) []string {
	t.Helper()
	raw, err := os.ReadFile(serverLog.Name())
	require.NoError(t, err)
	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.Contains(line, "audit="+event+" ") {
			out = append(out, line)
		}
	}
	return out
}

// TestE2E_AuditTrailCoversAccessAndTeamChanges checks that changes to who may do what are written
// to the audit log with the actor, the target and the outcome, including a refused attempt.
func TestE2E_AuditTrailCoversAccessAndTeamChanges(t *testing.T) {
	admin := request[profileEnvelope](t, http.MethodGet, "/api/v1/me", adminToken, nil, http.StatusOK)
	slug := newProject(t, "audit-trail")
	viewer := request[authResponse](t, http.MethodPost, "/api/v1/auth/register", "",
		map[string]string{"email": "audit-" + randomHex(4) + "@example.com", "password": adminPass}, http.StatusCreated)

	// A member is added, then removed.
	doJSON(t, http.MethodPost, "/api/v1/projects/"+slug+"/members", adminToken,
		map[string]string{"user_id": viewer.UserID, "role": "member"})
	doJSON(t, http.MethodDelete, "/api/v1/projects/"+slug+"/members/"+viewer.UserID, adminToken, nil)

	// A team is created and deleted.
	team := request[struct {
		ID string `json:"id"`
	}](t, http.MethodPost, "/api/v1/teams", adminToken,
		map[string]string{"name": "audit-" + randomHex(4)}, http.StatusCreated)
	doJSON(t, http.MethodDelete, "/api/v1/teams/"+team.ID, adminToken, nil)

	// A refused attempt is recorded as a failure.
	status, _ := doJSON(t, http.MethodPost, "/api/v1/teams", viewer.Token, map[string]string{"name": "nope"})
	require.Equal(t, http.StatusForbidden, status)

	added := auditLines(t, "project.member.add")
	require.NotEmpty(t, added)
	last := added[len(added)-1]
	require.Contains(t, last, "outcome=success")
	require.Contains(t, last, "principal_id="+admin.ID)
	require.Contains(t, last, "project="+slug)
	require.Contains(t, last, "target="+viewer.UserID)

	removed := auditLines(t, "project.member.remove")
	require.NotEmpty(t, removed)
	require.Contains(t, removed[len(removed)-1], "target="+viewer.UserID)

	require.NotEmpty(t, auditLines(t, "team.create"))
	deleted := auditLines(t, "team.delete")
	require.NotEmpty(t, deleted)
	require.Contains(t, deleted[len(deleted)-1], "target="+team.ID)

	created := auditLines(t, "team.create")
	require.Contains(t, created[len(created)-1], "outcome=failure", "the refused create is the latest entry")
	require.Contains(t, created[len(created)-1], "principal_id="+viewer.UserID)
}
