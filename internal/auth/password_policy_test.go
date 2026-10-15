package auth

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
)

func TestIsCommonPassword(t *testing.T) {
	cases := map[string]bool{
		"password1":    true,
		"12345678":     true,
		"PassWord1":    true,  // case folded
		"ＰＡＳＳＷＯＲＤ１":    true,  // fullwidth letters fold to ASCII under NFKC
		"password1 ":   false, // no trimming: the space makes it another password
		"password123":  false,
		"journey-x-17": false,
		"":             false,
	}
	for password, want := range cases {
		assert.Equal(t, want, IsCommonPassword(password), "%q", password)
	}
}

// The embedded list holds only entries the length rule would let through, in
// the folded form the lookup compares against, each once.
func TestCommonPasswordListShape(t *testing.T) {
	lines := strings.Split(strings.TrimSuffix(commonPasswordsText, "\n"), "\n")
	assert.Greater(t, len(lines), 1500)
	seen := make(map[string]bool, len(lines))
	for _, line := range lines {
		assert.GreaterOrEqual(t, utf8.RuneCountInString(line), 8, "%q", line)
		assert.Equal(t, foldPassword(line), line, "%q is not in folded form", line)
		assert.False(t, seen[line], "%q is listed twice", line)
		seen[line] = true
	}
}

func TestPasswordMatchesAccount(t *testing.T) {
	cases := []struct {
		name, password, email, display string
		want                           bool
	}{
		{"whole email", "ada@acme.example", "ada@acme.example", "", true},
		{"email in another case", "Ada@ACME.example", "ada@acme.example", "", true},
		{"local part", "ada.lovelace", "ada.lovelace@acme.example", "", true},
		{"display name", "Ada Lovelace", "x@acme.example", "ada lovelace", true},
		{"display name in fullwidth", "Ａｄａ Ｌｏｖｅｌａｃｅ", "x@acme.example", "Ada Lovelace", true},
		{"no trimming", " ada.lovelace", "ada.lovelace@acme.example", "", false},
		{"contains the name", "ada lovelace 1815", "x@acme.example", "Ada Lovelace", false},
		{"empty display name never matches", "", "x@acme.example", "", false},
		{"unrelated", "a-long-unrelated-phrase", "ada@acme.example", "Ada", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, PasswordMatchesAccount(tc.password, tc.email, tc.display))
		})
	}
}

// Default-ignorable code points draw nothing, so a password with one inside
// is the same password to the eye as the one without it.
func TestIsCommonPassword_IgnoresInvisibleCodePoints(t *testing.T) {
	for name, password := range map[string]string{
		"zero-width space":  "pass\u200bword1",
		"zero-width joiner": "pass\u200dword1",
		"soft hyphen":       "pass\u00adword1",
		"word joiner":       "pass\u2060word1",
		"byte order mark":   "pass\ufeffword1",
		"variation select":  "pass\ufe0fword1",
		"hangul filler":     "pass\u3164word1",
		"left-to-right":     "pass\u200eword1",
		"at the ends":       "\u200bpassword1\u2060",
	} {
		assert.True(t, IsCommonPassword(password), name)
	}
}

func TestPasswordMatchesAccount_IgnoresInvisibleCodePoints(t *testing.T) {
	assert.True(t, PasswordMatchesAccount("ada.love\u200blace", "ada.lovelace@acme.example", ""))
	assert.True(t, PasswordMatchesAccount("Ada\u00ad Lovelace", "x@acme.example", "Ada Lovelace"))
	assert.True(t, PasswordMatchesAccount("ada@acme.example", "ada\u200b@acme.example", ""))
}

func TestHasVisibleCharacter(t *testing.T) {
	cases := map[string]bool{
		"a":                  true,
		"  a  ":              true,
		"\u0301a":            true,
		"e\u0301":            true, // a mark on a letter is part of a visible character
		"😀":                  true,
		"        ":           false,
		"\t\n\u00a0\u3000":   false,
		"\u200b\u200b\u200b": false,
		"\u00ad\u2060\ufeff": false,
		"\u3164\uffa0":       false,
		"\ufe0f":             false,
		"\u0301\u0302\u0303": false, // marks with nothing to attach to
		" \u200b \u0301":     false,
		"":                   false,
	}
	for password, want := range cases {
		assert.Equal(t, want, HasVisibleCharacter(password), "%q", password)
	}
}
