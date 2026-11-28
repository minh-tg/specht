package repo

import (
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/db/sqlc"
)

// The announcer drops auto-rejected requests by status, so the mapping must keep
// the status the sweep returned. Without it every expired request was announced
// as an approved waiver that ended.
func TestExpiredWaiversKeepTheStatusTheSweepReturned(t *testing.T) {
	disabled := pgtype.UUID{Bytes: [16]byte{1}, Valid: true}
	rejected := pgtype.UUID{Bytes: [16]byte{2}, Valid: true}
	project := pgtype.UUID{Bytes: [16]byte{9}, Valid: true}

	got := expiredWaivers([]sqlc.ExpireWaiversRow{
		{ID: disabled, ProjectID: project, Name: "lodash", Status: "approved"},
		{ID: rejected, ProjectID: project, Name: "Waiver request: left-pad", Status: "rejected"},
	})

	require.Len(t, got, 2)
	assert.Equal(t, toUUID(disabled), got[0].ID)
	assert.Equal(t, toUUID(project), got[0].ProjectID)
	assert.Equal(t, "lodash", got[0].Name)
	assert.Equal(t, "approved", got[0].Status)
	assert.False(t, got[0].Enabled)
	assert.Equal(t, toUUID(rejected), got[1].ID)
	assert.Equal(t, "rejected", got[1].Status)
	assert.False(t, got[1].Enabled)
}
