package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMaskEmail(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"keeps first letter and domain", "ada@example.com", "a***@example.com"},
		{"normalises first", " Ada@Example.COM ", "a***@example.com"},
		{"single-letter local part", "a@example.com", "a***@example.com"},
		{"no at sign reveals nothing", "not-an-email", "***"},
		{"empty", "", "***"},
		{"leading at sign", "@example.com", "***@example.com"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, MaskEmail(tc.in))
		})
	}
}

func TestNormalizeEmail(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"already canonical", "ada@example.com", "ada@example.com"},
		{"mixed case", "Ada@Example.COM", "ada@example.com"},
		{"surrounding space", "  ada@example.com\t", "ada@example.com"},
		{"empty", "", ""},
		{"whitespace only", "   ", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, NormalizeEmail(tc.in))
		})
	}
}

// Runes whose lower case Go and PostgreSQL can disagree on. Go maps U+212A
// (Kelvin sign) to "k"; PostgreSQL's lower() maps it to "k" only under some
// locales, and the stock postgres:17-alpine image does. An address with one of
// them could therefore reach a different account in Go than in SQL, so the
// rule refuses them rather than guess a mapping.
var caseAmbiguousRunes = map[string]rune{
	"Kelvin sign":                  '\u212A',
	"Angstrom sign":                '\u212B',
	"capital I with dot above":     '\u0130',
	"capital sharp s":              '\u1E9E',
	"title-case dz with caron":     '\u01C5',
	"Latin capital E with acute":   '\u00C9',
	"Greek capital sigma":          '\u03A3',
	"Cyrillic capital De":          '\u0414',
	"fullwidth Latin capital A":    '\uFF21',
	"Ohm sign":                     '\u2126',
	"Roman numeral one":            '\u2160',
	"circled Latin capital letter": '\u24B6',
}

// Runes that are already lower case (or have no case) keep their form, so
// addresses that use them still work.
var caseStableRunes = map[string]rune{
	"Latin small e with acute": '\u00E9',
	"sharp s":                  '\u00DF',
	"dotless i":                '\u0131',
	"Greek final sigma":        '\u03C2',
	"Cyrillic small de":        '\u0434',
	"CJK ideograph":            '\u4E2D',
	"fullwidth digit one":      '\uFF11',
	"small dz with caron":      '\u01C6',
}

func TestNormalizeEmailRefusesRunesWhoseLowerCaseIsAmbiguous(t *testing.T) {
	for name, r := range caseAmbiguousRunes {
		for _, in := range []string{
			"ka" + string(r) + "te@example.com",
			"kate@corp" + string(r) + ".example",
			string(r) + "@example.com",
		} {
			assert.Empty(t, NormalizeEmail(in), name+": "+in)
			assert.False(t, FoldsConsistently(in), name+": "+in)
		}
	}
	kelvin := "\u212Aate@corp.example"
	assert.NotEqual(t, "kate@corp.example", NormalizeEmail(kelvin), "the Kelvin sign must not become a plain k")
}

func TestNormalizeEmailKeepsRunesThatAreAlreadyLowerCase(t *testing.T) {
	for name, r := range caseStableRunes {
		in := "Jo" + string(r) + "@Example.COM"
		assert.Equal(t, "jo"+string(r)+"@example.com", NormalizeEmail(in), name)
		assert.True(t, FoldsConsistently(in), name)
	}
}

func TestNormalizeEmailFoldsAsciiLettersOnly(t *testing.T) {
	assert.Equal(t, "abcdefghijklmnopqrstuvwxyz@example.com", NormalizeEmail("ABCDEFGHIJKLMNOPQRSTUVWXYZ@EXAMPLE.com"))
	assert.Equal(t, "k@example.com", NormalizeEmail("K@example.com"), "the ASCII K still folds")
}

func TestMaskEmailRevealsNothingForAnAmbiguousAddress(t *testing.T) {
	assert.Equal(t, "***", MaskEmail("\u212Aate@corp.example"))
}
