package auth

import (
	"net/url"
	"strings"
)

// maxSSOReturnPathBytes bounds the return path. It is stored in the login
// cookie, and a browser keeps several of those, so the limit keeps their
// total under the header size limits of common proxies.
const maxSSOReturnPathBytes = 1024

// safeSSOReturnPath returns raw when it is a same-origin path, or "/" when it
// is anything else. The result is checked after url.Parse has cleaned it, not
// only before: parsing decodes escapes and String() re-encodes them, so a
// string that passed the raw checks could come back as "//host/..." (for
// example "/%2Fevil.example/ "). Validating the output makes the function
// safe on its own and idempotent.
func safeSSOReturnPath(raw string) string {
	if !isLocalPath(raw) {
		return "/"
	}

	target, err := url.Parse(raw)
	if err != nil || target.IsAbs() || target.Host != "" || !strings.HasPrefix(target.Path, "/") {
		return "/"
	}
	// The SPA reserves the fragment for the SSO token, so only path and query
	// survive the login round-trip.
	target.Fragment = ""
	target.RawFragment = ""
	out := target.String()
	if !isLocalPath(out) {
		return "/"
	}
	return out
}

// isLocalPath reports whether s is "/" or starts with exactly one slash
// followed by a character that cannot begin a host: not another slash, not a
// backslash (browsers read both as a separator), and not an escaped form of
// either.
func isLocalPath(s string) bool {
	if s == "" || len(s) > maxSSOReturnPathBytes || s[0] != '/' || strings.ContainsAny(s, "\\\r\n\x00") {
		return false
	}
	if len(s) == 1 {
		return true
	}
	if s[1] == '/' {
		return false
	}
	rest := strings.ToLower(s[1:])
	return !strings.HasPrefix(rest, "%2f") && !strings.HasPrefix(rest, "%5c")
}
