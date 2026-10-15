package auth

import (
	_ "embed"
	"strings"
	"sync"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

// commonPasswordsText is SecLists' 10k-most-common.txt cut to the entries of
// at least 8 characters, lowercased and deduplicated. THIRD_PARTY_NOTICES in
// this directory names the source commit and carries its licence.
//
//go:embed common_passwords.txt
var commonPasswordsText string

var commonPasswords = sync.OnceValue(func() map[string]struct{} {
	lines := strings.Split(commonPasswordsText, "\n")
	set := make(map[string]struct{}, len(lines))
	for _, line := range lines {
		if line != "" {
			set[foldPassword(line)] = struct{}{}
		}
	}
	return set
})

// foldPassword is the form two passwords are compared in: NFKC, so a
// fullwidth or ligature letter equals its plain one, then case folded. It is
// only for comparing; the password that gets hashed is never changed.
func foldPassword(s string) string {
	return norm.NFKC.String(cases.Fold().String(norm.NFKC.String(s)))
}

// IsCommonPassword reports whether the password is on the embedded list of
// commonly used passwords, ignoring case and Unicode compatibility forms.
// Surrounding spaces are part of the password and are not trimmed.
func IsCommonPassword(password string) bool {
	_, ok := commonPasswords()[foldPassword(password)]
	return ok
}

// PasswordMatchesAccount reports whether the password equals the account's
// email address, the part of it before the at sign, or its display name,
// compared as IsCommonPassword compares. An empty email part or name matches
// nothing.
func PasswordMatchesAccount(password, email, displayName string) bool {
	folded := foldPassword(password)
	candidates := []string{email, displayName}
	if at := strings.LastIndex(email, "@"); at >= 0 {
		candidates = append(candidates, email[:at])
	}
	for _, c := range candidates {
		if c != "" && foldPassword(c) == folded {
			return true
		}
	}
	return false
}
