package scanner_test

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/scanner"
)

var nulEscape = fmt.Sprintf("%cu0000", 92)

func TestSourceNamesAvoidWindowsDevices(t *testing.T) {
	entries, err := os.ReadDir(".")
	require.NoError(t, err)
	reserved := regexp.MustCompile(`(?i)^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\.|$)`)
	for _, entry := range entries {
		assert.NotRegexp(t, reserved, entry.Name(), "scanner source must check out on Windows")
	}
}

func TestSanitizeNULDropsTheEscapeFromStringValues(t *testing.T) {
	cases := map[string]struct{ in, want string }{
		"middle":           {`{"a":"x` + nulEscape + `y"}`, `{"a":"xy"}`},
		"start":            {`{"a":"` + nulEscape + `xy"}`, `{"a":"xy"}`},
		"end":              {`{"a":"xy` + nulEscape + `"}`, `{"a":"xy"}`},
		"only":             {`{"a":"` + nulEscape + `"}`, `{"a":""}`},
		"repeated":         {`{"a":"` + nulEscape + nulEscape + `x` + nulEscape + `"}`, `{"a":"x"}`},
		"in array":         {`["a` + nulEscape + `","` + nulEscape + `b"]`, `["a","b"]`},
		"nested":           {`{"a":{"b":[{"c":"1` + nulEscape + `2"}]}}`, `{"a":{"b":[{"c":"12"}]}}`},
		"top level string": {`"a` + nulEscape + `b"`, `"ab"`},
		"two strings":      {`{"a":"x` + nulEscape + `","b":"` + nulEscape + `y"}`, `{"a":"x","b":"y"}`},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := scanner.SanitizeNUL([]byte(c.in))

			require.NoError(t, err)
			assert.Equal(t, c.want, string(got))
			assert.True(t, json.Valid(got))
		})
	}
}

// The escape for a backslash followed by the text u0000 is not a NUL.
func TestSanitizeNULLeavesEscapedBackslashesAlone(t *testing.T) {
	bs := string(rune(92))
	for _, in := range []string{
		`{"a":"` + bs + bs + `u0000"}`,
		`{"a":"x` + bs + bs + `u0000` + bs + bs + `"}`,
		`{"a":"` + bs + `u0001"}`,
		`{"a":"` + bs + `u00e9"}`,
		`{"a":"` + bs + `u000"}`, // too short to be an escape; the decoder refuses it
		`{"a":"` + bs + `n` + bs + `t` + bs + `"` + `"}`,
		`{"a":"plain"}`,
		``,
		`not json`,
		`{"a":"unterminated`,
	} {
		got, err := scanner.SanitizeNUL([]byte(in))
		require.NoError(t, err, in)
		assert.Equal(t, in, string(got), "nothing to remove")
	}
}

// An escaped backslash before the digits keeps the escape count right: the
// first backslash escapes the second, so the u0000 that follows is plain text,
// but a third backslash starts a real escape again.
func TestSanitizeNULCountsBackslashesFromTheLeft(t *testing.T) {
	bs := string(rune(92))
	in := `{"a":"` + bs + bs + bs + `u0000` + `"}` // escaped backslash, then a NUL escape
	got, err := scanner.SanitizeNUL([]byte(in))

	require.NoError(t, err)
	assert.Equal(t, `{"a":"`+bs+bs+`"}`, string(got))
}

func TestSanitizeNULReturnsTheSameBytesWhenThereIsNothingToRemove(t *testing.T) {
	data := []byte(`{"a":"` + strings.Repeat("x", 1000) + `"}`)

	got, err := scanner.SanitizeNUL(data)

	require.NoError(t, err)
	assert.Same(t, &data[0], &got[0], "no copy of a clean document, which can be 25 MiB")
}

func TestSanitizeNULDoesNotAllocateForACleanDocument(t *testing.T) {
	data := []byte(`{"a":["x","y"],"b":{"c":"d` + strings.Repeat("e", 10000) + `"}}`)
	allocs := testing.AllocsPerRun(10, func() { _, _ = scanner.SanitizeNUL(data) })
	assert.Zero(t, allocs)
}

// Dropping a NUL from a field name would rename the field, which changes what
// the parser reads and what redaction matches, so such a document is refused.
func TestSanitizeNULRefusesAFieldNameWithANUL(t *testing.T) {
	for _, in := range []string{
		`{"Secr` + nulEscape + `et":"x"}`,
		`{"a":{"` + nulEscape + `k":1}}`,
		`[{"k` + nulEscape + `" : 1}]`,
		`{"a":"fine","b` + nulEscape + `":[]}`,
	} {
		got, err := scanner.SanitizeNUL([]byte(in))

		require.ErrorIs(t, err, scanner.ErrMalformedReport, in)
		assert.Nil(t, got)
		assert.NotContains(t, err.Error(), "Secr", "the message does not echo the document")
	}
}

func TestSanitizeNULKeepsAValueThatLooksLikeAKey(t *testing.T) {
	// A string followed by a colon inside a string is not a key.
	in := `{"a":"` + nulEscape + `b\":c"}`
	got, err := scanner.SanitizeNUL([]byte(in))

	require.NoError(t, err)
	assert.Equal(t, `{"a":"b\":c"}`, string(got))
}
