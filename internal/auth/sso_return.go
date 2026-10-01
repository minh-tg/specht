package auth

import (
	"encoding/base64"
	"net/url"
	"strings"
)

const maxSSOReturnPathBytes = 2048

// SSOReturnCookieName names the cookie that binds a safe SPA return path to
// the corresponding OAuth state cookie.
const SSOReturnCookieName = "sso_return"

// EncodeSSOReturnCookieValue binds a validated same-origin return path to one
// OAuth state value. The callback accepts the path only with the matching state.
func EncodeSSOReturnCookieValue(state, returnPath string) string {
	encodedPath := base64.RawURLEncoding.EncodeToString([]byte(safeSSOReturnPath(returnPath)))
	return state + "~" + encodedPath
}

func decodeSSOReturnCookieValue(value, state string) string {
	boundState, encodedPath, ok := strings.Cut(value, "~")
	if !ok || !secureCompare(boundState, state) {
		return "/"
	}
	path, err := base64.RawURLEncoding.DecodeString(encodedPath)
	if err != nil {
		return "/"
	}
	return safeSSOReturnPath(string(path))
}

func safeSSOReturnPath(raw string) string {
	if raw == "" || len(raw) > maxSSOReturnPathBytes || !strings.HasPrefix(raw, "/") ||
		strings.ContainsAny(raw, "\\\r\n\x00") || (len(raw) > 1 && (raw[1] == '/' || raw[1] == '\\')) {
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
	return target.String()
}
