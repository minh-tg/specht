package auth

import (
	"strings"
	"unicode"
)

// FoldsConsistently reports whether the address lower-cases the same way in Go
// and in PostgreSQL. ASCII letters always do. Another rune is safe only when it
// is already lower case or has no case; one that has a lower case mapping (the
// Kelvin sign U+212A maps to "k" in Go and, depending on the database locale,
// in PostgreSQL's lower() too) is not, because the two sides could then reach
// different accounts, or one account under two spellings.
func FoldsConsistently(email string) bool {
	for _, r := range email {
		if r < unicode.MaxASCII {
			continue
		}
		if unicode.ToLower(r) != r || unicode.IsUpper(r) || unicode.IsTitle(r) {
			return false
		}
	}
	return true
}

// NormalizeEmail returns the canonical form of an account email: surrounding
// whitespace removed and ASCII letters lowercased. Account identity is
// case-insensitive, so every path that looks up or stores an address (password
// login, registration, SSO, admin bootstrap) must go through this one rule.
//
// An address with a rune that FoldsConsistently refuses has no canonical form
// and normalizes to the empty string, which every caller already treats as no
// address: registration and invites answer "invalid email address", sign-in and
// SSO find no account.
func NormalizeEmail(email string) string {
	email = strings.TrimSpace(email)
	if !FoldsConsistently(email) {
		return ""
	}
	return asciiLower(email)
}

// asciiLower lowercases the ASCII letters and leaves every other byte alone.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
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
