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
// characters stripped: category Cc except tab and newline, and the
// bidirectional formatting controls U+202A to U+202E and U+2066 to U+2069.
// Other format characters (Cf) such as the zero-width joiner U+200D, the soft
// hyphen U+00AD and the byte-order mark U+FEFF are kept, because stripping
// them garbles emoji sequences and legitimate text. Everything else, including
// plain text, tabs and newlines, is kept.
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
		if unicode.Is(unicode.Cc, r) || isBidiControl(r) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// isBidiControl reports whether r is a Unicode bidirectional formatting
// control. In a terminal these can reorder or hide the surrounding text.
func isBidiControl(r rune) bool {
	return (r >= '\u202a' && r <= '\u202e') || (r >= '\u2066' && r <= '\u2069')
}

// needsStripping reports whether s holds a control character or the start of
// an escape sequence, so plain text is returned without the copy.
func needsStripping(s string) bool {
	for _, r := range s {
		if r == '\t' || r == '\n' {
			continue
		}
		if unicode.Is(unicode.Cc, r) || isBidiControl(r) {
			return true
		}
	}
	return false
}

// Line returns s as a single line of plain text that is safe to print into a
// CI log. It removes ANSI escape sequences, control characters and
// bidirectional formatting controls as Text does, turns every line break,
// tab and line or paragraph separator into a space, collapses runs of
// whitespace, and keeps a leading "::" from reading as a GitHub Actions
// workflow command by putting a space in front of it. The CI runner parses a
// line that starts with "::" as a command, so a scanner-supplied title must
// never open a line that way.
func Line(s string) string {
	s = strings.Map(func(r rune) rune {
		switch r {
		case '\n', '\r', '\t', '\v', '\f', '\u0085', ' ', ' ':
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(Text(s)), " ")
	if strings.HasPrefix(s, "::") {
		return " " + s
	}
	return s
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
