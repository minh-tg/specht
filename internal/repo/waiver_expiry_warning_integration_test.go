//go:build integration

package repo

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
)

// A waiver warned about once and then given a new end date is warned about again
// before that date. An edit that keeps the end date does not warn twice.
func TestANewWaiverExpiryRearmsTheWarning(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	project := createTestProject(t, repos)
	stores := NewPortStores(repos.pool)
	expiry := NewWaiverExpiryStore(repos.pool)

	inTwoDays := time.Now().Add(48 * time.Hour).Truncate(time.Second)
	waiver, err := stores.Waivers.CreateWithDetails(ctx, port.CreateWaiverInput{
		ProjectID: toUUID(project.ID), Name: "lodash", Enabled: true, ExpiresAt: &inTwoDays,
		Event: port.WaiverEventInput{EventType: "created", Metadata: []byte(`{}`)},
	})
	require.NoError(t, err)

	claim := func() []port.Waiver {
		t.Helper()
		claimed, err := expiry.ClaimExpiring(ctx, time.Now().Add(7*24*time.Hour))
		require.NoError(t, err)
		return claimed
	}
	update := func(name string, newExpiry *port.WaiverExpiry) {
		t.Helper()
		_, err := stores.Waivers.UpdateWithDetails(ctx, port.Waiver{
			ID: waiver.ID, ProjectID: toUUID(project.ID), Name: name,
		}, newExpiry, nil, nil, nil, port.WaiverEventInput{EventType: "updated", Metadata: []byte(`{}`)})
		require.NoError(t, err)
	}

	require.Len(t, claim(), 1, "the first sweep in the window warns")
	assert.Empty(t, claim(), "a warned waiver is not warned about twice")

	update("lodash (renamed)", nil)
	assert.Empty(t, claim(), "an edit that leaves the expiry alone keeps the warning claimed")

	sameDay := inTwoDays
	update("", &port.WaiverExpiry{At: &sameDay})
	assert.Empty(t, claim(), "writing the same expiry again keeps the warning claimed")

	inFiveDays := time.Now().Add(5 * 24 * time.Hour).Truncate(time.Second)
	update("", &port.WaiverExpiry{At: &inFiveDays})
	claimed := claim()
	require.Len(t, claimed, 1, "an extended waiver warns again before its new end")
	assert.Equal(t, waiver.ID, claimed[0].ID)
	require.NotNil(t, claimed[0].ExpiresAt)
	assert.WithinDuration(t, inFiveDays, *claimed[0].ExpiresAt, time.Second)
	assert.Empty(t, claim(), "the new warning is claimed once too")
}
