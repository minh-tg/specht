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
