//go:build e2e

package e2e

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/client"
)

// The Go client library as a subject — its methods driven against
// the live server (the CLI already exercises a subset end to end).

func TestE2E_ClientLibrarySweep(t *testing.T) {
	cl := client.New(baseURL, client.WithToken(adminToken))
	slug := newProject(t, "client-sweep")
	ingestFixture(t, slug, adminToken, "high-medium.sarif.json")
	findings := listScanFindings(t, slug)
	require.Len(t, findings, 2)
	highID := ""
	for _, f := range findings {
		if f.CurrentSeverity == "high" {
			highID = f.ID
		}
	}
	require.NotEmpty(t, highID)

	t.Run("identity and platform reads", func(t *testing.T) {
		_, err := cl.Health()
		require.NoError(t, err)
		me, err := cl.Me()
		require.NoError(t, err)
		require.Equal(t, adminEmail, me.Email)
		admin, err := cl.GetAdminStatus()
		require.NoError(t, err)
		require.Positive(t, admin.Projects)
		scanners, err := cl.ListScanners()
		require.NoError(t, err)
		require.Len(t, scanners, 11)
	})

	t.Run("project, findings, gate, reports", func(t *testing.T) {
		projects, err := cl.ListProjects()
		require.NoError(t, err)
		var listed bool
		for _, p := range projects {
			if p.Slug == slug {
				listed = true
			}
		}
		require.True(t, listed)

		proj, err := cl.GetProject(slug)
		require.NoError(t, err)
		require.Equal(t, slug, proj.Slug)

		fs, err := cl.ListFindings(slug, nil, nil, 50, 0)
		require.NoError(t, err)
		require.Len(t, fs, 2)

		f, err := cl.GetFinding(highID)
		require.NoError(t, err)
		require.Equal(t, "high", f.CurrentSeverity)

		gate, err := cl.GetGateStatus(slug, "")
		require.NoError(t, err)
		require.True(t, gate.ThresholdBreached,
			"the high finding breaches the default floor")

		reports, err := cl.ListReports(slug, 10, 0)
		require.NoError(t, err)
		require.NotEmpty(t, reports)
		rep, err := cl.GetReport(reports[0].ID)
		require.NoError(t, err)
		require.Equal(t, "completed", rep.Status)
	})

	t.Run("context tables, policy, teams, keys and watcher answer", func(t *testing.T) {
		_, err := cl.ListEnvironments(slug)
		require.NoError(t, err)
		_, err = cl.ListTargets(slug)
		require.NoError(t, err)
		_, err = cl.ListArtifacts(slug)
		require.NoError(t, err)
		_, err = cl.GetWatcherStatus()
		require.NoError(t, err)
		_, err = cl.GetEffectivePolicy(slug)
		require.NoError(t, err)
		_, err = cl.ListTeams()
		require.NoError(t, err)
		_, err = cl.ListPolicyTemplates()
		require.NoError(t, err)
		key := mintKey(t, slug)
		keys, err := cl.ListAPIKeys(slug)
		require.NoError(t, err)
		var listed bool
		for _, k := range keys {
			if strings.HasPrefix(key, k.KeyPrefix) {
				listed = true
			}
		}
		require.True(t, listed, "the minted key is listed with its prefix")
	})

	t.Run("waiver mutations round-trip including the expiry tri-state", func(t *testing.T) {
		expires := time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)
		w, err := cl.CreateWaiver(slug, &client.CreateWaiverRequest{
			Name:      "client-window",
			ExpiresAt: expires,
			TargetIDs: []string{highID},
		})
		require.NoError(t, err)
		require.NotEmpty(t, w.ExpiresAt)

		det, err := cl.GetWaiver(slug, w.ID)
		require.NoError(t, err)
		require.NotEmpty(t, det.ExpiresAt)

		matched, err := cl.CheckWaiverMatch(slug, highID)
		require.NoError(t, err)
		require.True(t, matched)
		gate, err := cl.GetGateStatus(slug, "")
		require.NoError(t, err)
		require.False(t, gate.ThresholdBreached, "the waiver silences the gate")

		// nil keeps the stored expiry...
		kept, err := cl.UpdateWaiver(slug, w.ID, &client.UpdateWaiverRequest{
			Name: "client-window-renamed",
		})
		require.NoError(t, err)
		require.NotEmpty(t, kept.ExpiresAt)

		// ...a value replaces it...
		newExpiry := time.Now().Add(4 * time.Hour).UTC().Format(time.RFC3339)
		set, err := cl.UpdateWaiver(slug, w.ID, &client.UpdateWaiverRequest{
			ExpiresAt: &newExpiry,
		})
		require.NoError(t, err)
		require.NotEmpty(t, set.ExpiresAt)

		// ...and a pointer to "" clears it (a plain string with omitempty
		// could never express this — the shape is the contract).
		empty := ""
		cleared, err := cl.UpdateWaiver(slug, w.ID, &client.UpdateWaiverRequest{
			ExpiresAt: &empty,
		})
		require.NoError(t, err)
		require.Empty(t, cleared.ExpiresAt)

		events, err := cl.ListWaiverEvents(slug, w.ID)
		require.NoError(t, err)
		var types []string
		for _, e := range events {
			types = append(types, e.EventType)
		}
		require.Contains(t, types, "created")
		require.Contains(t, types, "updated")

		require.NoError(t, cl.DeleteWaiver(slug, w.ID))
	})

	t.Run("previews answer and errors surface", func(t *testing.T) {
		patch, err := cl.PreviewPatch(highID)
		require.NoError(t, err)
		require.NotNil(t, patch)

		_, err = cl.GetProject("no-such-project")
		require.Error(t, err, "a live 404 becomes a client error")
		_, err = cl.GetReport(randomHex(16))
		require.Error(t, err)
	})
}
