package sanitize

import (
	"bytes"
	"strings"
	"testing"
)

func TestText(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain text is unchanged", "CVE-2024-0001 in libc", "CVE-2024-0001 in libc"},
		{"tabs and newlines are kept", "tab\there\nand newline", "tab\there\nand newline"},
		{"ANSI color sequence is removed", "red\x1b[31mwarning\x1b[0m", "redwarning"},
		{"CSI clear sequence is removed", "a\x1b[2Jb", "ab"},
		{"OSC sequence is removed", "a\x1b]0;title\x07b", "ab"},
		{"bidi right-to-left override is removed", "safe\u202egnihs", "safegnihs"},
		{"bidi isolate controls are removed", "a\u2066b\u2069c", "abc"},
		{"zero-width joiner emoji sequence is kept", "\U0001f468\u200d\U0001f469\u200d\U0001f467", "\U0001f468\u200d\U0001f469\u200d\U0001f467"},
		{"soft hyphen is kept", "soft\u00adhyphen", "soft\u00adhyphen"},
		{"byte-order mark is kept", "\ufefftitle", "\ufefftitle"},
		{"C0 controls are removed", "a\x00b\x07c\x1bd", "abcd"},
		{"C1 controls are removed", "a\u0085b\u009fc", "abc"},
		{"carriage return is removed", "line\r\nnext", "line\nnext"},
		{"non-Latin text is kept", "日本語 ✓", "日本語 ✓"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Text(tc.in); got != tc.want {
				t.Fatalf("Text(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestLine(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain text is unchanged", "CVE-2024-0001 in libc", "CVE-2024-0001 in libc"},
		{"newlines become spaces", "libfoo 1.0\n::notice::forged\n::add-mask::x", "libfoo 1.0 ::notice::forged ::add-mask::x"},
		{"carriage returns and tabs become spaces", "a\r\nb\tc", "a b c"},
		{"line and paragraph separators become spaces", "a b c\u0085d", "a b c d"},
		{"runs of whitespace collapse", "a \n\n  b", "a b"},
		{"ANSI sequences are removed", "x\x1b[2J\x1b[31mred", "xred"},
		{"bidi overrides are removed", "feat/‮tnirp", "feat/tnirp"},
		{"a leading workflow command prefix is defused", "::stop-commands::tok", " ::stop-commands::tok"},
		{"a leading prefix after newlines is defused", "\n\n::notice::x", " ::notice::x"},
		{"a prefix inside the line is kept", "a ::b", "a ::b"},
		{"non-Latin text is kept", "日本語 ✓", "日本語 ✓"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Line(tc.in)
			if got != tc.want {
				t.Fatalf("Line(%q) = %q, want %q", tc.in, got, tc.want)
			}
			if strings.ContainsAny(got, "\n\r\x1b") {
				t.Fatalf("Line(%q) = %q still holds a line break or escape", tc.in, got)
			}
		})
	}
}

func TestWriterStripsEachWrite(t *testing.T) {
	var out bytes.Buffer
	w := Writer(&out)
	if _, err := w.Write([]byte("ok\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("bad\x1b[31m\u202e\n")); err != nil {
		t.Fatal(err)
	}
	if got, want := out.String(), "ok\nbad\n"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if n, err := w.Write([]byte("x")); err != nil || n != 1 {
		t.Fatalf("Write returned %d, %v; want 1, nil", n, err)
	}
}

func TestWriterNilStaysNil(t *testing.T) {
	if Writer(nil) != nil {
		t.Fatal("Writer(nil) must stay nil")
	}
}

func TestTextStripsEveryASCIIControlExceptTabAndNewline(t *testing.T) {
	for r := rune(0); r < 0x20; r++ {
		in := "a" + string(r) + "b"
		got := Text(in)
		if r == '\t' || r == '\n' {
			if got != in {
				t.Fatalf("Text kept %q as %q, want %q", in, got, in)
			}
			continue
		}
		if strings.ContainsRune(got, r) {
			t.Fatalf("Text(%q) = %q, still holds %q", in, got, r)
		}
	}
}
