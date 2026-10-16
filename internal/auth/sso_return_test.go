package auth

import (
	"strings"
	"testing"
)

func TestSafeSSOReturnPath(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "empty defaults home", in: "", want: "/"},
		{name: "internal path and query", in: "/projects/demo?tab=members", want: "/projects/demo?tab=members"},
		{name: "fragment is reserved for the token", in: "/projects/demo#details", want: "/projects/demo"},
		{name: "absolute URL", in: "https://evil.example/path", want: "/"},
		{name: "protocol relative", in: "//evil.example/path", want: "/"},
		{name: "backslash protocol relative", in: `/\evil.example/path`, want: "/"},
		{name: "embedded backslash", in: `/safe\path`, want: "/"},
		{name: "overlong path", in: "/" + strings.Repeat("a", maxSSOReturnPathBytes), want: "/"},
		// Found by fuzzing: url.Parse decodes %2F, and re-encoding the cleaned
		// path used to yield a protocol-relative "//evil.example/%20".
		{name: "encoded slash then invalid byte", in: "/%2Fevil.example/ ", want: "/"},
		{name: "encoded slash", in: "/%2Fevil.example/", want: "/"},
		{name: "encoded backslash", in: "/%5Cevil.example/", want: "/"},
		{name: "encoded slash after a segment is kept", in: "/a%2Fb", want: "/a%2Fb"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := safeSSOReturnPath(tt.in); got != tt.want {
				t.Errorf("safeSSOReturnPath(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestSafeSSOReturnPathIsIdempotent(t *testing.T) {
	for _, in := range []string{
		"", "/", "/%2Fevil.example/ ", "/%2F%2Fevil.example", "/a%2F%2Fb", "/projects/demo?tab=members",
		"/x?next=//evil.example", "/%252Fevil.example", "/ ", "/\u00e9", "/a b/c",
	} {
		once := safeSSOReturnPath(in)
		if twice := safeSSOReturnPath(once); twice != once {
			t.Errorf("safeSSOReturnPath(%q) = %q, then %q: not idempotent", in, once, twice)
		}
		assertSameOriginPath(t, in, once)
	}
}

// assertSameOriginPath fails unless out is "/" or starts with one slash
// followed by a character that cannot turn the path into a host.
func assertSameOriginPath(t *testing.T, in, out string) {
	t.Helper()
	if out == "" || out[0] != '/' {
		t.Fatalf("safeSSOReturnPath(%q) = %q: not an absolute path", in, out)
	}
	if len(out) > 1 && (out[1] == '/' || out[1] == '\\') {
		t.Fatalf("safeSSOReturnPath(%q) = %q: protocol relative", in, out)
	}
	if strings.ContainsAny(out, "\\\r\n\x00") {
		t.Fatalf("safeSSOReturnPath(%q) = %q: forbidden character", in, out)
	}
}

func FuzzSafeSSOReturnPath(f *testing.F) {
	for _, seed := range []string{
		"", "/", "/projects/demo?tab=members", "//evil.example", "/%2Fevil.example/ ", "/\\evil.example",
		"/%5Cevil.example", "https://evil.example", "/a#frag", "/a%00b", "/%252F", "/ ",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, in string) {
		once := safeSSOReturnPath(in)
		assertSameOriginPath(t, in, once)
		if twice := safeSSOReturnPath(once); twice != once {
			t.Fatalf("safeSSOReturnPath(%q) = %q, then %q: not idempotent", in, once, twice)
		}
	})
}
