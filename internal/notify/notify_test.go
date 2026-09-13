package notify

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func baseInput() Input {
	return Input{
		FindingID: "f1", Title: "XSS in handler", Severity: "high",
		SeverityRank: 3, FindingKind: "sast", Fingerprint: "fp1",
		State: "open", ProjectSlug: "my-app", Channel: ChannelIssue,
		Target: "SEC", Remediation: "https://example.com/fix",
	}
}

func TestBuild_IssueCreate(t *testing.T) {
	out := Build(baseInput())
	require.True(t, out.Supported)
	require.NotNil(t, out.Plan)
	p := out.Plan
	assert.Equal(t, ChannelIssue, p.Channel)
	assert.Equal(t, ActionCreate, p.Action)
	assert.Equal(t, "SEC", p.Target)
	assert.Contains(t, p.Title, "HIGH")
	assert.Contains(t, p.Body, "fp1")
	assert.NotEmpty(t, p.DedupeKey)

	again := Build(baseInput())
	assert.Equal(t, p.ID, again.Plan.ID, "identical evidence reproduces the identical plan")
	assert.Equal(t, p.DedupeKey, again.Plan.DedupeKey)
}

func TestBuild_UpdateAndClose(t *testing.T) {
	in := baseInput()
	in.AlreadyLinked = true
	out := Build(in)
	require.True(t, out.Supported)
	assert.Equal(t, ActionUpdate, out.Plan.Action)

	in = baseInput()
	in.AlreadyLinked = true
	in.State = "fixed"
	out = Build(in)
	require.True(t, out.Supported)
	assert.Equal(t, ActionClose, out.Plan.Action, "fixed findings resolve linked items")
}

func TestBuild_UnknownStateNeverCloses(t *testing.T) {
	in := baseInput()
	in.AlreadyLinked = true
	in.State = "quarantined"
	out := Build(in)
	require.True(t, out.Supported)
	assert.Equal(t, ActionUpdate, out.Plan.Action)
}

func TestBuild_MessageSubject(t *testing.T) {
	in := baseInput()
	in.Channel = ChannelMessage
	in.Target = "#security"
	out := Build(in)
	require.True(t, out.Supported)
	assert.Contains(t, out.Plan.Title, "new")
	assert.Equal(t, "#security", out.Plan.Target)
}

func TestBuild_Refusals(t *testing.T) {
	out := Build(Input{})
	assert.False(t, out.Supported)
	assert.Nil(t, out.Plan)
	assert.Contains(t, out.Reason, "unsupported channel")

	in := baseInput()
	in.Target = "  "
	out = Build(in)
	assert.False(t, out.Supported)
	assert.Contains(t, out.Reason, "target is required")

	in = baseInput()
	in.Fingerprint = ""
	out = Build(in)
	assert.False(t, out.Supported)
	assert.Contains(t, out.Reason, "dedupe")
}
