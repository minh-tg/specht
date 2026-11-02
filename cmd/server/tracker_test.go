package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildTrackerDispatcher_LogsAnUnknownProvider(t *testing.T) {
	logs := captureBootstrapLogs(t)

	d := buildTrackerDispatcher("jira")
	require.NotNil(t, d)
	require.NoError(t, d.Close())

	assert.Contains(t, logs.String(), "level=ERROR")
	assert.Contains(t, logs.String(), "unknown TRACKER_PROVIDER")
	assert.Contains(t, logs.String(), "provider=jira")
}

func TestBuildTrackerDispatcher_KnownProvidersStaySilent(t *testing.T) {
	for _, provider := range []string{"", "noop", "inprocess"} {
		logs := captureBootstrapLogs(t)
		d := buildTrackerDispatcher(provider)
		require.NoError(t, d.Close())
		assert.NotContains(t, logs.String(), "level=ERROR", provider)
	}
}
