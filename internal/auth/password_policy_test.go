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
