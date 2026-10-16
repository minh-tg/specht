//go:build e2e

package e2e

import (
	"context"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// TestE2E_WaiverUpdateAndDeleteAreAuditedAndKeepAnArchive: a waiver update and
// a waiver delete each leave an audit line naming the actor, the project and
// the waiver, and the delete keeps the waiver's identity and event trail in
// waiver_deletions instead of cascading it away.
func TestE2E_WaiverUpdateAndDeleteAreAuditedAndKeepAnArchive(t *testing.T) {
	slug := newProject(t, "waiver-audit")
	key := mintKey(t, slug)
	ingestFixture(t, slug, key, "high-medium.sarif.json")
	target := highFinding(t, slug)
	admin := request[profileEnvelope](t, http.MethodGet, "/api/v1/me", adminToken, nil, http.StatusOK)

	waiver := createWaiver(t, slug, "audited-waiver", target.ID, "")
	waiverPath := "/api/v1/projects/" + slug + "/waivers/" + waiver.ID

	request[waiverDetail](t, http.MethodPut, waiverPath, adminToken,
		map[string]string{"description": "changed"}, http.StatusOK)
	updated := auditLines(t, "waiver.update")
	require.NotEmpty(t, updated, "the update leaves an audit line")
	last := updated[len(updated)-1]
	require.Contains(t, last, "outcome=success")
	require.Contains(t, last, "principal_id="+admin.ID)
	require.Contains(t, last, "project="+slug)
	require.Contains(t, last, "target="+waiver.ID)

	status, _ := doJSON(t, http.MethodDelete, waiverPath, adminToken, nil)
	require.Equal(t, http.StatusNoContent, status)
	deleted := auditLines(t, "waiver.delete")
	require.NotEmpty(t, deleted, "the delete leaves an audit line")
	last = deleted[len(deleted)-1]
	require.Contains(t, last, "outcome=success")
	require.Contains(t, last, "principal_id="+admin.ID)
	require.Contains(t, last, "project="+slug)
	require.Contains(t, last, "target="+waiver.ID)

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	var deletedBy, name string
	var events int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT deleted_by, snapshot->'waiver'->>'name', jsonb_array_length(snapshot->'events')
		  FROM waiver_deletions WHERE waiver_id = $1`, waiver.ID).Scan(&deletedBy, &name, &events))
	require.Equal(t, admin.ID, deletedBy)
	require.Equal(t, "audited-waiver", name)
	require.Equal(t, 2, events, "created and updated survive the delete")

	// The waiver itself is gone from the API and from the gate.
	status, _ = doJSON(t, http.MethodGet, waiverPath, adminToken, nil)
	require.Equal(t, http.StatusNotFound, status)
	require.True(t, getGate(t, slug, "").ThresholdBreached, "a deleted waiver no longer silences the gate")
}
