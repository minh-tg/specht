//go:build integration

package repo

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAgingReopenedIsATechnicalReopen(t *testing.T) {
	s, cleanup := newScopeSeverityScenario(t)
	defer cleanup()

	insert := func(eventType, newValue string) {
		t.Helper()
		_, err := s.pool.Exec(s.ctx,
			`INSERT INTO finding_events (finding_id, event_type, old_value, new_value, changes) VALUES ($1, $2, 'open', $3, '{}')`,
			s.findingID, eventType, newValue)
		require.NoError(t, err)
	}
	rows, _, err := s.stores.Stats.GetAgingRows(s.ctx, s.projectID)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.False(t, rows[0].Reopened, "a finding nobody has changed is not reopened")

	insert("reopened_severity_change", "open")
	rows, _, err = s.stores.Stats.GetAgingRows(s.ctx, s.projectID)
	require.NoError(t, err)
	require.False(t, rows[0].Reopened, "a material-change review is not a technical reopen")

	insert("reopened_fix_available", "open")
	rows, _, err = s.stores.Stats.GetAgingRows(s.ctx, s.projectID)
	require.NoError(t, err)
	require.False(t, rows[0].Reopened, "a fix becoming available is not a technical reopen")

	insert("regression", "reopened")
	rows, _, err = s.stores.Stats.GetAgingRows(s.ctx, s.projectID)
	require.NoError(t, err)
	require.True(t, rows[0].Reopened)
}
