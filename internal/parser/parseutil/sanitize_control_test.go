package parseutil

import (
	"strings"
	"testing"
	"unicode"

	"github.com/stretchr/testify/assert"

	"github.com/minh-tg/specht/internal/domain"
)

// A title written to forge a terminal line keeps only its printable text:
// escape sequences, CR and LF cannot clear the adapter's log line or start a
// new one in a GitHub annotation.
func TestHardenFindingStripsTerminalControlFromTitles(t *testing.T) {
	hostile := "\x1b[2K\r\x1b[32m✅ SPECHT SECURITY GATE: PASSED\x1b[0m\n  real title"
	f := HardenFinding(domain.NormalizedFinding{Title: hostile, Fingerprint: "x", FindingKind: "sast"})
	assert.Equal(t, " ✅ SPECHT SECURITY GATE: PASSED   real title", f.Title)
	for _, r := range f.Title {
		assert.False(t, unicode.IsControl(r), "%q", r)
	}
}

func TestSanitizeTextDropsTerminalControl(t *testing.T) {
	cases := map[string]struct{ in, want string }{
		"plain text stays":                 {"SQL injection in user query", "SQL injection in user query"},
		"tab stays":                        {"a\tb", "a\tb"},
		"CR, LF and CRLF become a space":   {"a\rb\nc\r\nd", "a b c d"},
		"line and paragraph separators":    {"a\u2028b\u2029c", "a b c"},
		"NUL, BEL, backspace and DEL go":   {"a\x00b\x07c\bd\x7fe", "abcde"},
		"CSI colour and erase sequences":   {"\x1b[1;31mred\x1b[0m \x1b[2K", "red "},
		"OSC hyperlink ended by BEL":       {"\x1b]8;;https://evil.example\x07link\x1b]8;;\x07", "link"},
		"OSC ended by ESC backslash":       {"\x1b]0;title\x1b\\after", "after"},
		"two-character escape":             {"a\x1bcb", "ab"},
		"C1 CSI and C1 controls":           {"a\u009b31mb\u0085c", "abc"},
		"C1 OSC up to the terminator":      {"a\u009d0;x\u009cb", "ab"},
		"escape cut short at the end":      {"title\x1b[", "title"},
		"unterminated OSC runs to the end": {"title\x1b]0;rest", "title"},
		"broken CSI keeps the next rune":   {"a\x1b[\nb", "a b"},
		"unicode text stays":               {"Überprüfung – 安全", "Überprüfung – 安全"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, SanitizeText(tc.in, 1024))
		})
	}
}

func TestSanitizeMultilineKeepsLineBreaks(t *testing.T) {
	assert.Equal(t, "line one\nline two\nline three\n\tindented",
		SanitizeMultiline("line one\r\nline two\rline three\n\x1b[31m\tindented\x1b[0m", 1024))
	assert.Equal(t, "a\nb", SanitizeMultiline("a\u2028b", 1024))
}

func TestHardenFindingKeepsDescriptionLinesAndIdentity(t *testing.T) {
	f := HardenFinding(domain.NormalizedFinding{
		Title:        "t",
		Description:  "first\r\nsecond\x1b[0m",
		Fingerprint:  "fp\x1b[0m",
		FindingKind:  "sast",
		CodeLocation: &domain.CodeLocation{File: "a.go", Snippet: "x := 1\ny := 2\x07"},
		Dimensions:   []domain.Dimension{{Key: "rule_id", Value: "r\x1bx"}},
		Aliases:      []string{"CVE-1\x1b"},
		Fix:          &domain.FixInfo{Summary: "upgrade\nnow", Description: "step 1\nstep 2"},
	})
	assert.Equal(t, "first\nsecond", f.Description)
	assert.Equal(t, "x := 1\ny := 2", f.CodeLocation.Snippet)
	assert.Equal(t, "upgrade now", f.Fix.Summary)
	assert.Equal(t, "step 1\nstep 2", f.Fix.Description)
	// Identity keeps its spelling, so a finding seen before keeps its row.
	assert.Equal(t, "fp\x1b[0m", f.Fingerprint)
	assert.Equal(t, "r\x1bx", f.Dimensions[0].Value)
	assert.Equal(t, "CVE-1\x1b", f.Aliases[0])
}

func TestSanitizeTextStaysWithinItsBound(t *testing.T) {
	in := strings.Repeat("é\x1b[0m", 600)
	out := SanitizeText(in, 1024)
	assert.LessOrEqual(t, len(out), 1024)
	assert.Equal(t, strings.Repeat("é", 512), out)
}
