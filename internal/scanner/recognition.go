package scanner

import (
	"errors"
	"fmt"
	"strings"
)

// Recognition grades how sure a scanner is that a document is its output.
type Recognition int

const (
	// NotRecognized means the document is not this scanner's output.
	NotRecognized Recognition = iota
	// Possible means the document has this scanner's envelope but holds too
	// little to be sure, for example a report with no results. Another
	// scanner may still claim it for certain.
	Possible
	// Definite means the document is positively this scanner's output.
	Definite
)

func (r Recognition) String() string {
	switch r {
	case Definite:
		return "definite"
	case Possible:
		return "possible"
	default:
		return "not recognized"
	}
}

// Recognizer is implemented by scanners that can grade a document, which lets
// them tell an empty report of their own from another tool's output. A
// scanner that does not implement it is graded by DetectFormat alone:
// Definite or NotRecognized.
type Recognizer interface {
	Recognize(data []byte) Recognition
}

// Recognize grades data against s, using its own grading when it has one.
func Recognize(s Scanner, data []byte) Recognition {
	if r, ok := s.(Recognizer); ok {
		return r.Recognize(data)
	}
	if s.DetectFormat(data) {
		return Definite
	}
	return NotRecognized
}

var (
	// ErrUnrecognizedFormat is returned when a document is not the named
	// scanner's output. Handlers map it to a 422 the person can act on.
	ErrUnrecognizedFormat = errors.New("report format not recognized")
	// ErrMalformedReport is returned when a document has the scanner's
	// envelope but its content cannot be read, for example a field of the
	// wrong type.
	ErrMalformedReport = errors.New("report could not be read")
)

// UnrecognizedFormatError says which scanner was named and, when another
// scanner positively recognizes the document, which ones it looks like. The
// text names only registered scanners, so it is safe to show to the caller.
type UnrecognizedFormatError struct {
	Scanner   string
	LooksLike []string
}

func (e *UnrecognizedFormatError) Error() string {
	msg := "the data is not " + e.Scanner + " output"
	if len(e.LooksLike) > 0 {
		msg += "; it looks like " + strings.Join(e.LooksLike, " or ") + " output"
	}
	return msg
}

// Is lets errors.Is(err, ErrUnrecognizedFormat) match.
func (e *UnrecognizedFormatError) Is(target error) bool { return target == ErrUnrecognizedFormat }

// Unrecognized is what a parser returns for a document that is not its format.
func Unrecognized(scanner string) error {
	return &UnrecognizedFormatError{Scanner: scanner}
}

// Malformed wraps a read failure of a document that has the scanner's
// envelope. Both ErrMalformedReport and the cause stay matchable.
func Malformed(scanner string, cause error) error {
	return fmt.Errorf("%s: %w: %w", scanner, ErrMalformedReport, cause)
}

// MalformedDetailError carries an optional explanation a caller can act on,
// such as the version a file declares or a NUL in a field name. The detail must
// never carry report content beyond a short value the producer wrote.
type MalformedDetailError struct {
	Detail string
	cause  error
}

func (e *MalformedDetailError) Error() string { return e.Detail }

// Unwrap keeps the underlying cause reachable.
func (e *MalformedDetailError) Unwrap() error { return e.cause }

// Detail wraps cause with a caller-safe explanation of why a report is malformed.
func Detail(detail string, cause error) error {
	return &MalformedDetailError{Detail: detail, cause: cause}
}

// MalformedDetail returns the caller-safe explanation in err, if one was given.
func MalformedDetail(err error) (string, bool) {
	var detail *MalformedDetailError
	if errors.As(err, &detail) {
		return detail.Detail, true
	}
	return "", false
}

// CheckFormat decides whether data may be parsed as the named scanner's
// output. A definite match always passes. A possible match (an empty report)
// passes unless another scanner is positively sure the document is its own,
// and anything else is refused. A refusal names the scanners the document
// looks like so the caller can pick the right one.
func (r *Registry) CheckFormat(name string, data []byte) error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	named, ok := r.byName[name]
	if !ok {
		return fmt.Errorf("%w: %q", ErrNoMatch, name)
	}
	grade := Recognize(named, data)
	if grade == Definite {
		return nil
	}
	var others []string
	for _, reg := range r.scanners {
		if reg.name != name && Recognize(reg.sc, data) == Definite {
			others = append(others, reg.name)
		}
	}
	if grade == Possible && len(others) == 0 {
		return nil
	}
	return &UnrecognizedFormatError{Scanner: name, LooksLike: others}
}
