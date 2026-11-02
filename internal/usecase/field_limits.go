package usecase

import (
	"errors"
	"fmt"
	"unicode"
	"unicode/utf8"
)

const (
	// MaxNameChars is the longest API key or project name accepted, counted in
	// characters after trimming so a name in any script gets the same room.
	MaxNameChars = 100
	// MaxDescriptionChars is the longest project description accepted.
	MaxDescriptionChars = 2000
)

// ErrInvalidField means a free-text field is too long or holds a control
// character. The wrapped message names the field. Handlers map it to 400
// invalid_field.
var ErrInvalidField = errors.New("invalid field")

// checkName validates a one-line name as it will be stored (already trimmed):
// at most MaxNameChars characters and no control characters, so a name cannot
// carry a terminal escape into the key list or the CLI.
func checkName(field, value string) error {
	return checkText(field, value, MaxNameChars, false)
}

// checkDescription validates a description as it will be stored. It may span
// lines, so newline, carriage return and tab are allowed; any other control
// character is not.
func checkDescription(field, value string) error {
	return checkText(field, value, MaxDescriptionChars, true)
}

func checkText(field, value string, maxChars int, multiline bool) error {
	// A rune is at most four bytes, so a value over four times the limit is
	// too long without being counted.
	if len(value) > maxChars*utf8.UTFMax || utf8.RuneCountInString(value) > maxChars {
		return fmt.Errorf("%w: %s must be at most %d characters", ErrInvalidField, field, maxChars)
	}
	for _, r := range value {
		if !unicode.IsControl(r) {
			continue
		}
		if multiline && (r == '\n' || r == '\r' || r == '\t') {
			continue
		}
		return fmt.Errorf("%w: %s must not contain control characters", ErrInvalidField, field)
	}
	return nil
}
