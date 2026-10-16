package scanner

import (
	"context"
	"errors"
	"fmt"
)

const (
	// DefaultMaxFindings is the number of findings and packages one report may
	// produce when the context carries no limit.
	DefaultMaxFindings = 100000

	// ObjectsPerFinding bounds how many JSON objects a document may hold per
	// allowed finding. A finding needs a handful of nested objects (CVSS blocks,
	// locations, identifiers); a document far past that is hostile. The count is
	// taken before the document is decoded, because decoding materializes every
	// object as a struct and would otherwise run first.
	ObjectsPerFinding = 10
)

// ErrTooManyFindings is returned when a report would produce more findings
// than the instance allows. Handlers map it to a 422.
var ErrTooManyFindings = errors.New("report has too many findings")

// TooManyFindingsError carries the limit that was exceeded.
type TooManyFindingsError struct{ Limit int }

func (e *TooManyFindingsError) Error() string {
	return fmt.Sprintf("%v: the limit is %d", ErrTooManyFindings, e.Limit)
}

// Is makes the error match ErrTooManyFindings.
func (e *TooManyFindingsError) Is(target error) bool { return target == ErrTooManyFindings }

// TooManyFindings builds the error for a report that went past limit.
func TooManyFindings(limit int) error { return &TooManyFindingsError{Limit: limit} }

type maxFindingsContext struct{}

// WithMaxFindings returns a context that carries the finding limit for Parse.
func WithMaxFindings(ctx context.Context, limit int) context.Context {
	return context.WithValue(ctx, maxFindingsContext{}, limit)
}

// MaxFindings returns the finding limit in ctx. A missing, zero or negative
// limit is DefaultMaxFindings, never unlimited.
func MaxFindings(ctx context.Context) int {
	if n, _ := ctx.Value(maxFindingsContext{}).(int); n > 0 {
		return n
	}
	return DefaultMaxFindings
}

// CheckDocument refuses a JSON document that holds more than
// limit*ObjectsPerFinding objects. It reads the bytes once and allocates
// nothing, so it can run before any decoder sees the document. Input that is not
// valid JSON passes: reporting that is the decoder's job.
func CheckDocument(data []byte, limit int) error {
	if limit <= 0 {
		limit = DefaultMaxFindings
	}
	ceiling := limit * ObjectsPerFinding
	objects := 0
	for i := 0; i < len(data); i++ {
		switch data[i] {
		case '"':
			i = skipString(data, i)
		case '{':
			if objects++; objects > ceiling {
				return TooManyFindings(limit)
			}
		}
	}
	return nil
}

// skipString returns the index of the quote that closes the string opened at
// data[start], or the last index when the string is cut off.
func skipString(data []byte, start int) int {
	for i := start + 1; i < len(data); i++ {
		switch data[i] {
		case '\\':
			i++
		case '"':
			return i
		}
	}
	return len(data) - 1
}
