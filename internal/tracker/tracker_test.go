package tracker

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInProcessTracker_CreateAndVerifyFixed(t *testing.T) {
	tr := NewInProcessTracker(nil)

	created, err := tr.CreateIssue(context.Background(), Event{
		Type:        EventCreated,
		FindingID:   "find-1",
		ProjectSlug: "my-app",
		Severity:    "high",
		Title:       "CVE-2024-1234",
		Fingerprint: "fp1",
		FindingKind: "sca",
		OccurredAt:  time.Now(),
	})
	require.NoError(t, err)
	assert.NotEmpty(t, created)

	issues := tr.Issues()
	require.Len(t, issues, 1)
	assert.Equal(t, "open", issues[0].State)
	assert.Equal(t, "find-1", issues[0].FindingID)

	err = tr.UpdateIssue(context.Background(), created, Event{
		Type:        EventVerifiedFixed,
		FindingID:   "find-1",
		ProjectSlug: "my-app",
		OccurredAt:  time.Now(),
	})
	require.NoError(t, err)

	issues = tr.Issues()
	require.Len(t, issues, 1)
	assert.Equal(t, "closed", issues[0].State)
	assert.Len(t, issues[0].Transitions, 1)
	assert.Equal(t, "open", issues[0].Transitions[0].From)
	assert.Equal(t, "closed", issues[0].Transitions[0].To)
}

func TestInProcessTracker_RegressionReopens(t *testing.T) {
	tr := NewInProcessTracker(nil)

	_, err := tr.CreateIssue(context.Background(), Event{
		Type:        EventCreated,
		FindingID:   "find-reg",
		ProjectSlug: "app",
		Severity:    "critical",
		Title:       "CVE-2024-9999",
		Fingerprint: "fp2",
		FindingKind: "sca",
	})
	require.NoError(t, err)

	// Regression: finding reappears → reopened.
	err = tr.UpdateIssue(context.Background(), "", Event{
		Type:        EventRegression,
		FindingID:   "find-reg",
		ProjectSlug: "app",
		OccurredAt:  time.Now(),
	})
	require.NoError(t, err)

	issues := tr.Issues()
	require.Len(t, issues, 1)
	assert.Equal(t, "reopened", issues[0].State)
	assert.Len(t, issues[0].Transitions, 1)
	assert.Equal(t, "open", issues[0].Transitions[0].From)
	assert.Equal(t, "reopened", issues[0].Transitions[0].To)
}

func TestNoopTracker(t *testing.T) {
	n := NoopTracker{}
	id, err := n.CreateIssue(context.Background(), Event{Type: EventCreated, FindingID: "f1"})
	require.NoError(t, err)
	assert.Equal(t, IssueID(""), id)
	assert.NoError(t, n.UpdateIssue(context.Background(), "", Event{Type: EventRegression, FindingID: "f1"}))
	assert.Equal(t, "noop", n.Name())
}

func TestResolveConfig(t *testing.T) {
	c := ResolveConfig()
	assert.Equal(t, "noop", c.Provider)
}
