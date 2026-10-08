package auth

import "strings"

// NormalizeEmail returns the canonical form of an account email: surrounding
// whitespace removed and lowercased. Account identity is case-insensitive, so
// every path that looks up or stores an address (password login, registration,
// SSO, admin bootstrap) must go through this one rule.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// MaskEmail returns a log-safe form of an address: the first letter of the
// local part and the domain, for example "a***@example.com". It keeps a trace
// recognisable to an operator without writing the full personal address to
// logs. Input without an at sign yields "***".
func MaskEmail(email string) string {
	email = NormalizeEmail(email)
	at := strings.LastIndex(email, "@")
	if at < 0 {
		return "***"
	}
	local, domain := email[:at], email[at:]
	if local == "" {
		return "***" + domain
	}
	return local[:1] + "***" + domain
}
