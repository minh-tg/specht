package auth

import (
	_ "embed"
	"strings"
	"sync"
	"unicode"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

// commonPasswordsText is SecLists' 10k-most-common.txt cut to the entries of
// at least 8 characters, lowercased and deduplicated. THIRD_PARTY_NOTICES at
// the repository root names the source commit and carries its licence.
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

// foldPassword is the form two passwords are compared in: invisible code
// points dropped, NFKC so a fullwidth or ligature letter equals its plain one,
// then case folded. It is only for comparing; the password that gets hashed is
// never changed.
func foldPassword(s string) string {
	return norm.NFKC.String(cases.Fold().String(norm.NFKC.String(dropInvisible(s))))
}

// isInvisible reports whether r draws nothing by itself: the Unicode
// Default_Ignorable_Code_Point set, written out as its parts. That is the
// format category Cf (zero-width space, joiners, soft hyphen, word joiner,
// byte order mark, bidirectional marks), the variation selectors, and
// Other_Default_Ignorable_Code_Point (Hangul fillers and the like). NFKC leaves
// all of these in place.
func isInvisible(r rune) bool {
	return unicode.Is(unicode.Cf, r) ||
		unicode.Is(unicode.Variation_Selector, r) ||
		unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r)
}

func dropInvisible(s string) string {
	return strings.Map(func(r rune) rune {
		if isInvisible(r) {
			return -1
		}
		return r
	}, s)
}

// HasVisibleCharacter reports whether the password has a character a person
// can see: one that is not white space, not invisible (see isInvisible) and
// not a combining mark, which needs a base to draw on.
func HasVisibleCharacter(password string) bool {
	return strings.IndexFunc(password, func(r rune) bool {
		return !isInvisible(r) && !unicode.IsSpace(r) && !unicode.Is(unicode.Z, r) && !unicode.Is(unicode.M, r)
	}) >= 0
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
