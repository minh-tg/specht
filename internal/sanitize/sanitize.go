// Package sanitize removes terminal control characters from text that came
// from scan output or stored strings. A finding title or path is attacker
// controlled, so an ANSI escape sequence or a bidirectional override in it
// would otherwise rewrite the terminal or hide text.
package sanitize

import (
	"io"
	"regexp"
	"strings"
	"unicode"
)

// ansiEscape matches ANSI escape sequences: CSI (ESC [), OSC (ESC ]) and the
// shorter ESC sequences. The alternation puts the sequences with a payload
// first, so ESC [ is not consumed as a two-byte sequence and leaves "[31m"
// behind as literal text.
var ansiEscape = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]|\x9b[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]`)

// Text returns s with ANSI escape sequences removed and with Unicode control
// characters stripped: category Cc except tab and newline, and category Cf,
// which holds the bidirectional overrides U+202A to U+202E and U+2066 to
// U+2069. Everything else, including plain text, tabs and newlines, is kept.
func Text(s string) string {
	if !needsStripping(s) {
		return s
	}
	s = ansiEscape.ReplaceAllString(s, "")
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == '\t' || r == '\n' {
			b.WriteRune(r)
			continue
		}
		if unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// needsStripping reports whether s holds a control character or the start of
// an escape sequence, so plain text is returned without the copy.
func needsStripping(s string) bool {
	for _, r := range s {
		if r == '\t' || r == '\n' {
			continue
		}
		if unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r) {
			return true
		}
	}
	return false
}

// Writer returns w wrapped so Text runs on every write before it reaches w.
// fmt writes a formatted result in one call, so an escape sequence passed as
// an argument is removed as a whole.
func Writer(w io.Writer) io.Writer {
	if w == nil {
		return nil
	}
	return &writer{w: w}
}

type writer struct {
	w io.Writer
}

func (s *writer) Write(p []byte) (int, error) {
	if _, err := io.WriteString(s.w, Text(string(p))); err != nil {
		return 0, err
	}
	return len(p), nil
}
