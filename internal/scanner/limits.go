package scanner

import (
	"context"
	"errors"
	"fmt"
	"slices"
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
	ObjectsPerFinding = 16

	// ElementsPerFinding bounds the objects in a parser's finding arrays per
	// allowed finding. Some elements are skipped (suppressed results, entries
	// without a rule id), so the bound is above one.
	ElementsPerFinding = 2

	// maxScanDepth is the nesting depth encoding/json accepts. Past it the
	// decoder reports the error, so the scan stops following containers.
	maxScanDepth = 10000
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

// CheckDocument refuses a JSON document that would decode into more than the
// limit allows. It reads the bytes once and allocates nothing, so it can run
// before any decoder sees the document. Input that is not valid JSON passes:
// reporting that is the decoder's job.
//
// Two counts apply. Every document may hold at most limit*ObjectsPerFinding
// objects. When arrayKeys name the arrays that carry findings (the JSON key the
// array sits under, or "" for a top-level array or one object per line), the
// objects inside those arrays may number at most limit*ElementsPerFinding. The
// second count is what keeps a parser that decodes a whole array into structs
// before it converts any of them from holding millions of structs.
func CheckDocument(data []byte, limit int, arrayKeys ...string) error {
	if limit <= 0 {
		limit = DefaultMaxFindings
	}
	objectCeiling := limit * ObjectsPerFinding
	elementCeiling := limit * ElementsPerFinding
	track := len(arrayKeys) > 0
	rootCounts := slices.Contains(arrayKeys, "")

	var stack []byte // one flag byte per open container
	objects, elements := 0, 0
	keyCounts := false // the key just read names a counted array
	top := func() (flags byte, open bool) {
		if len(stack) == 0 {
			return 0, false
		}
		return stack[len(stack)-1], true
	}
	for i := 0; i < len(data); i++ {
		switch data[i] {
		case '"':
			end := skipString(data, i)
			if track {
				keyCounts = false
				if flags, open := top(); open && flags&frameArray == 0 && isKey(data, end) {
					keyCounts = containsKey(arrayKeys, data[i+1:end])
				}
			}
			i = end
		case '{':
			if objects++; objects > objectCeiling {
				return TooManyFindings(limit)
			}
			if track {
				flags, open := top()
				if (open && flags&frameArray != 0 && flags&frameCounts != 0) || (!open && rootCounts) {
					if elements++; elements > elementCeiling {
						return TooManyFindings(limit)
					}
				}
				stack = append(stack, 0)
				keyCounts = false
			}
		case '[':
			if track {
				var counts bool
				switch flags, open := top(); {
				case !open:
					counts = rootCounts
				case flags&frameArray != 0:
					counts = flags&frameCounts != 0
				default:
					counts = keyCounts
				}
				frame := frameArray
				if counts {
					frame |= frameCounts
				}
				stack = append(stack, frame)
				keyCounts = false
			}
		case '}', ']':
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			keyCounts = false
		}
		if len(stack) > maxScanDepth {
			return nil
		}
	}
	return nil
}

// Container flags kept on the scan stack.
const (
	frameArray  byte = 1 // the container is an array
	frameCounts byte = 2 // the array's elements count toward the element ceiling
)

// isKey reports whether the string that ends at data[end] is followed by a colon.
func isKey(data []byte, end int) bool {
	for j := end + 1; j < len(data); j++ {
		switch data[j] {
		case ' ', '\t', '\n', '\r':
		default:
			return data[j] == ':'
		}
	}
	return false
}

func containsKey(keys []string, key []byte) bool {
	for _, k := range keys {
		if string(key) == k {
			return true
		}
	}
	return false
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
