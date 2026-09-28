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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := safeSSOReturnPath(tt.in); got != tt.want {
				t.Errorf("safeSSOReturnPath(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestDecodeSSOReturnCookieValueBindsState(t *testing.T) {
	const state = "csrf.nonce"
	value := EncodeSSOReturnCookieValue(state, "/projects/demo?tab=members")
	if got := decodeSSOReturnCookieValue(value, state); got != "/projects/demo?tab=members" {
		t.Fatalf("decode with matching state = %q", got)
	}
	if got := decodeSSOReturnCookieValue(value, "other-state"); got != "/" {
		t.Fatalf("decode with mismatched state = %q, want root", got)
	}
	if got := decodeSSOReturnCookieValue(state+"~!", state); got != "/" {
		t.Fatalf("decode malformed return cookie = %q, want root", got)
	}
}
