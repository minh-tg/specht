package gate

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEvaluateFailsClosedWhenWaiverPolicyCannotBeLoaded(t *testing.T) {
	storeErr := errors.New("waiver scope query failed")
	g := New(
		&mockFindingsRepo{findings: []Finding{{ID: "finding-1", CurrentSeverityRank: 4}}},
		&mockWaiversRepo{err: storeErr},
	)

	decision, err := g.Evaluate(context.Background(), "project-1", 3)

	require.ErrorIs(t, err, storeErr)
	assert.Equal(t, StatusError, decision.Status)
	assert.Empty(t, decision.BlockedBy)
	assert.Zero(t, decision.WaivedCount)
}
