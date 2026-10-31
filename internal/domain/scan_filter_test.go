package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeScanFilter(t *testing.T) {
	got, err := NormalizeScanFilter([]string{"CRITICAL", " High", "high", "Low"}, true)
	require.NoError(t, err)
	assert.Equal(t, []string{"low", "high", "critical"}, got.Severities)
	assert.True(t, got.FixableOnly)
	assert.False(t, got.IsZero())

	empty, err := NormalizeScanFilter([]string{}, false)
	require.NoError(t, err)
	assert.Nil(t, empty.Severities)
	assert.True(t, empty.IsZero())

	_, err = NormalizeScanFilter([]string{"high", "severe"}, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"severe"`)
}
