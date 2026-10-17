package scanner_test

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/scanner"
)

func TestCapRawEvidence_KeepsOutputUpToTheCapAsItIs(t *testing.T) {
	data := []byte(`{"a":"` + strings.Repeat("x", scanner.RawEvidenceCap-len(`{"a":""}`)) + `"}`)
	require.Len(t, data, scanner.RawEvidenceCap)

	assert.Equal(t, data, scanner.CapRawEvidence(data, len(data)))
}

func TestCapRawEvidence_CutsAboveTheCapWithTheMarkerAndOriginalSize(t *testing.T) {
	redacted := []byte(`{"a":"` + strings.Repeat("x", 200<<10) + `"}`)
	original := len(redacted) + 17 // the unredacted output was larger

	out := scanner.CapRawEvidence(redacted, original)

	var got struct {
		Truncated     bool   `json:"truncated"`
		OriginalBytes int    `json:"original_bytes"`
		Prefix        string `json:"prefix"`
	}
	require.NoError(t, json.Unmarshal(out, &got), "the stored value stays one JSON document")
	assert.True(t, got.Truncated)
	assert.Equal(t, original, got.OriginalBytes)
	assert.Equal(t, string(redacted[:scanner.RawEvidenceCap]), got.Prefix)
	assert.Less(t, len(out), scanner.RawEvidenceCap+100, "the stored form is the cap plus the wrapper")
}

// A cut that lands inside a multi-byte character backs off to the character's
// start, so the stored prefix is valid UTF-8 and keeps no partial rune.
func TestCapRawEvidence_CutsOnAUTF8Boundary(t *testing.T) {
	redacted := []byte(`"` + strings.Repeat("a", scanner.RawEvidenceCap-2) + `é` + `"`)
	require.Greater(t, len(redacted), scanner.RawEvidenceCap)

	out := scanner.CapRawEvidence(redacted, len(redacted))

	var got struct {
		Prefix string `json:"prefix"`
	}
	require.NoError(t, json.Unmarshal(out, &got))
	// Byte RawEvidenceCap is the second byte of "é", so the cut backs off to its first byte.
	assert.Equal(t, string(redacted[:scanner.RawEvidenceCap-1]), got.Prefix)
	assert.True(t, utf8.ValidString(got.Prefix))
}
