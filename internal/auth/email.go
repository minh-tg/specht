package auth

import "strings"

// NormalizeEmail returns the canonical form of an account email: surrounding
// whitespace removed and lowercased. Account identity is case-insensitive, so
// every path that looks up or stores an address (password login, registration,
// SSO, admin bootstrap) must go through this one rule.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
