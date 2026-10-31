package watcher

import (
	"encoding/json"
	"strings"
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
	var got struct {
		Attachments []map[string]any `json:"attachments"`
	}
	require.NoError(t, json.Unmarshal(raw, &got))
	require.Len(t, got.Attachments, 1)
	joined, err := json.Marshal(got.Attachments[0])
	require.NoError(t, err)
	decoded := string(joined)
	for _, bad := range []string{"<!channel>", "<!here>", "<!everyone>", "<@U123>", "<https://evil.example"} {
		assert.NotContains(t, strings.ReplaceAll(decoded, "\\u003c", "<"), bad)
	}
	assert.Equal(t, "&lt;!channel&gt; &lt;https://evil.example|Fix now&gt; &amp; more", got.Attachments[0]["title"])
}

func TestSlackEscapeEscapesAmpersandFirst(t *testing.T) {
	assert.Equal(t, "&amp;lt; &lt; &gt; &amp;", slackEscape("&lt; < > &"))
}
