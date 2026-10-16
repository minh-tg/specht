package usecase

import (
	"errors"
	"fmt"
	"unicode/utf8"
)

const (
	// MaxEmailBytes is the longest email address accepted, the RFC 5321 path
	// limit. It counts bytes because the address is stored and sent as bytes.
	MaxEmailBytes = 254
	// MaxDisplayNameChars is the longest display name accepted, counted in
	// characters (after trimming) so a name in any script gets the same room.
	MaxDisplayNameChars = 100
)

var (
	errEmailTooLong       = fmt.Errorf("email address must be at most %d bytes", MaxEmailBytes)
	errDisplayNameTooLong = fmt.Errorf("display name must be at most %d characters", MaxDisplayNameChars)
)

// ErrInvalidProfileInput means a profile update was refused because a field
// breaks a rule. The wrapped message says which. Handlers map it to a 400.
var ErrInvalidProfileInput = errors.New("invalid profile")

// checkEmailLength is the one place that decides whether an email address is
// too long. Every flow that accepts an address calls it before parsing, so an
// oversized value is refused without being scanned, and wraps the result in
// the error shape that flow already answers with.
func checkEmailLength(email string) error {
	if len(email) > MaxEmailBytes {
		return errEmailTooLong
	}
	return nil
}

// checkDisplayNameLength is the display name counterpart of checkEmailLength.
// Pass the name as it will be stored, already trimmed.
func checkDisplayNameLength(name string) error {
	if utf8.RuneCountInString(name) > MaxDisplayNameChars {
		return errDisplayNameTooLong
	}
	return nil
}
