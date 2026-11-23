package watcher

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildSlackPayloadEscapesSlackControlSequences(t *testing.T) {
	hostile := Notification{
		Title:    "<!channel> <https://evil.example|Fix now> & more",
		CVE:      "<!here>",
		Package:  "pkg:npm/<@U123>",
		Project:  "<!everyone> web",
		Severity: "high",
	}

	raw, err := BuildSlackPayload([]Notification{hostile})

	require.NoError(t, err)
	var got slackPayload
	require.NoError(t, json.Unmarshal(raw, &got))
	require.Len(t, got.Attachments, 1)
	att := got.Attachments[0]
	assert.Equal(t, "&lt;!channel&gt; &lt;https://evil.example|Fix now&gt; &amp; more", att.Title)
	values := map[string]string{}
	for _, f := range att.Fields {
		values[f.Title] = f.Value
	}
	assert.Equal(t, "&lt;!here&gt;", values["CVE"])
	assert.Equal(t, "pkg:npm/&lt;@U123&gt;", values["Package"])
	assert.Equal(t, "&lt;!everyone&gt; web", values["Project"])
	for _, text := range []string{att.Title, att.Fallback, values["CVE"], values["Package"], values["Project"]} {
		assert.NotContains(t, text, "<")
		assert.NotContains(t, text, ">")
	}
}

// A waiver notice puts the acting person's display name in the message text. Any member sets
// their own display name, so it must not reach Slack as a mention or a link.
func TestBuildSlackPayloadEscapesTheHeading(t *testing.T) {
	raw, err := BuildSlackPayload([]Notification{{
		Title:   "lodash",
		Heading: "Waiver requested by <!channel> <https://evil.example/login|Sign in again> & co",
	}})

	require.NoError(t, err)
	var got slackPayload
	require.NoError(t, json.Unmarshal(raw, &got))
	assert.Equal(t,
		"Waiver requested by &lt;!channel&gt; &lt;https://evil.example/login|Sign in again&gt; &amp; co",
		got.Text)
	assert.NotContains(t, got.Text, "<")
}

func TestSlackEscapeEscapesAmpersandFirst(t *testing.T) {
	assert.Equal(t, "&amp;lt; &lt; &gt; &amp;", slackEscape("&lt; < > &"))
}
