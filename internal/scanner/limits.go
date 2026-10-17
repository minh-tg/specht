package scanner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"unicode/utf16"
	"unicode/utf8"
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

	// ElementsPerFinding bounds the elements in a parser's finding arrays per
	// allowed finding, whatever their type: a null, a string or a number decodes
	// into a zero struct or an interface value just as an object does. Some
	// elements are skipped (suppressed results, entries without a rule id), so
	// the bound is above one.
	ElementsPerFinding = 2

	// ValuesPerFinding bounds every JSON value in a document (object, array,
	// string, number, true, false and null; object keys are not values) per
	// allowed finding. It catches padding that sits inside one finding's fields,
	// such as a string array with millions of entries, where no counted finding
	// array grows. The captured reports under internal/parser/testdata hold 16
	// to 140 values per finding (OSV-Scanner is the densest, because its fixed
	// metadata is spread over three findings) and a Trivy report of minimal
	// findings about 10, so 64 accepts all of them at the default limit. At the
	// default limit the 25 MiB body cap holds fewer values than the ceiling
	// allows for any report with real findings in it.
	ValuesPerFinding = 64

	// MaxNestingDepth is the deepest a report body may nest JSON objects and
	// arrays. A 200-level document reaches 67x its size in peak memory while a
	// parser decodes it, above the 64x the field bounds charge, so anything
	// deeper is refused before a parser runs. The deepest real scanner fixture
	// under e2e/testdata or internal/parser/testdata nests 14 levels.
	MaxNestingDepth = 64
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
// limit allows. It reads the bytes once and allocates nothing per value, so it
// can run before any decoder sees the document. Input that is not valid JSON
// passes unless it nests too deep: reporting a syntax error is the decoder's job.
//
// Three counts apply. Every document may hold at most limit*ObjectsPerFinding
// objects and limit*ValuesPerFinding values of any kind. When arrayKeys name the
// arrays that carry findings (the JSON key the array sits under, or "" for a
// top-level array or one value per line), the elements of those arrays, of any
// type, may number at most limit*ElementsPerFinding. The last count keeps a
// parser that decodes a whole array into structs before it converts any of them
// from holding millions of structs.
//
// Array keys match the way encoding/json matches struct fields: ignoring case
// and after JSON escapes are decoded, so "Results", "RESULTS" and a spelling
// that uses a unicode escape all name the same array. A key whose decoded form
// is longer than maxKeyLen bytes never matches.
//
// A document that nests deeper than MaxNestingDepth is refused whatever its
// counts, with the same TooManyFindingsError. Only the containers the scan opens
// count toward the depth, so brackets inside strings do not.
func CheckDocument(data []byte, limit int, arrayKeys ...string) error {
	if limit <= 0 {
		limit = DefaultMaxFindings
	}
	s := docScan{
		objectCeiling:  limit * ObjectsPerFinding,
		elementCeiling: limit * ElementsPerFinding,
		valueCeiling:   limit * ValuesPerFinding,
		track:          len(arrayKeys) > 0,
		rootCounts:     slices.Contains(arrayKeys, ""),
		limit:          limit,
	}
	for _, k := range arrayKeys {
		s.keys = append(s.keys, []byte(k))
	}
	var frames [MaxNestingDepth]byte
	s.stack = frames[:0]

	for i := 0; i < len(data); i++ {
		var err error
		switch data[i] {
		case ' ', '\t', '\n', '\r', ',', ':':
		case '"':
			end := skipString(data, i)
			if s.inObject() && isKey(data, end) {
				if s.track {
					s.keyCounts = s.matchesKey(data[i+1 : end])
				}
			} else {
				err = s.value(false)
			}
			i = end
		case '{':
			if err = s.value(true); err == nil {
				s.push(0)
			}
		case '[':
			frame := frameArray
			if s.arrayCounts() {
				frame |= frameCounts
			}
			if err = s.value(false); err == nil {
				s.push(frame)
			}
		case '}', ']':
			if len(s.stack) > 0 {
				s.stack = s.stack[:len(s.stack)-1]
			}
			s.keyCounts = false
		default:
			// A number, true, false, null, or garbage the decoder will refuse.
			end := i
			for end+1 < len(data) && !isDelimiter(data[end+1]) {
				end++
			}
			err = s.value(false)
			i = end
		}
		if err != nil {
			return err
		}
		if len(s.stack) > MaxNestingDepth {
			return TooManyFindings(MaxNestingDepth)
		}
	}
	return nil
}

// maxKeyLen is the longest decoded array key that can match. The parsers' array
// keys are short names; the bound lets a key be decoded into a stack buffer.
const maxKeyLen = 64

// Container flags kept on the scan stack.
const (
	frameArray  byte = 1 // the container is an array
	frameCounts byte = 2 // the array's elements count toward the element ceiling
)

// docScan is the state of one CheckDocument pass.
type docScan struct {
	limit                                       int
	objectCeiling, elementCeiling, valueCeiling int
	objects, elements, values                   int
	track, rootCounts                           bool
	keys                                        [][]byte
	stack                                       []byte // one flag byte per open container
	keyCounts                                   bool   // the key just read names a counted array
}

func (s *docScan) push(frame byte) { s.stack = append(s.stack, frame) }

// inObject reports whether the innermost open container is an object.
func (s *docScan) inObject() bool {
	return len(s.stack) > 0 && s.stack[len(s.stack)-1]&frameArray == 0
}

// elementCounts reports whether a value that starts now is an element of a
// counted array. Values at the top level are elements when "" is a counted key.
func (s *docScan) elementCounts() bool {
	if len(s.stack) == 0 {
		return s.rootCounts
	}
	f := s.stack[len(s.stack)-1]
	return f&frameArray != 0 && f&frameCounts != 0
}

// arrayCounts reports whether an array that starts now is a counted one: the
// array under a counted key, or an array nested directly in a counted array.
func (s *docScan) arrayCounts() bool {
	if len(s.stack) == 0 || s.stack[len(s.stack)-1]&frameArray != 0 {
		return s.elementCounts()
	}
	return s.keyCounts
}

// value records one JSON value starting here and checks the ceilings.
func (s *docScan) value(isObject bool) error {
	if s.values++; s.values > s.valueCeiling {
		return TooManyFindings(s.limit)
	}
	if isObject {
		if s.objects++; s.objects > s.objectCeiling {
			return TooManyFindings(s.limit)
		}
	}
	if s.track && s.elementCounts() {
		if s.elements++; s.elements > s.elementCeiling {
			return TooManyFindings(s.limit)
		}
	}
	s.keyCounts = false
	return nil
}

// matchesKey reports whether the raw object key (the bytes between its quotes)
// names one of the counted arrays.
func (s *docScan) matchesKey(raw []byte) bool {
	if bytes.IndexByte(raw, '\\') >= 0 {
		var buf [maxKeyLen]byte
		decoded, ok := unescapeKey(buf[:0], raw)
		if !ok {
			return false
		}
		raw = decoded
	}
	for _, k := range s.keys {
		if bytes.EqualFold(raw, k) {
			return true
		}
	}
	return false
}

// unescapeKey appends the decoded form of a JSON string body to dst, which must
// have room for maxKeyLen bytes. It reports false for an invalid escape or when
// the result would not fit.
func unescapeKey(dst, raw []byte) ([]byte, bool) {
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c != '\\' {
			if len(dst)+1 > cap(dst) {
				return nil, false
			}
			dst = append(dst, c)
			continue
		}
		i++
		if i >= len(raw) {
			return nil, false
		}
		var r rune
		switch raw[i] {
		case '"', '\\', '/':
			r = rune(raw[i])
		case 'b':
			r = '\b'
		case 'f':
			r = '\f'
		case 'n':
			r = '\n'
		case 'r':
			r = '\r'
		case 't':
			r = '\t'
		case 'u':
			var ok bool
			if r, ok = hex4(raw, i+1); !ok {
				return nil, false
			}
			i += 4
			if utf16.IsSurrogate(r) {
				// A pair is two escapes; a lone half decodes to U+FFFD.
				if i+6 < len(raw) && raw[i+1] == '\\' && raw[i+2] == 'u' {
					if low, ok := hex4(raw, i+3); ok {
						if pair := utf16.DecodeRune(r, low); pair != utf8.RuneError {
							r = pair
							i += 6
						}
					}
				}
				if utf16.IsSurrogate(r) {
					r = utf8.RuneError
				}
			}
		default:
			return nil, false
		}
		if len(dst)+utf8.RuneLen(r) > cap(dst) {
			return nil, false
		}
		dst = utf8.AppendRune(dst, r)
	}
	return dst, true
}

// hex4 reads four hex digits at raw[at:].
func hex4(raw []byte, at int) (rune, bool) {
	if at+4 > len(raw) {
		return 0, false
	}
	var r rune
	for _, c := range raw[at : at+4] {
		switch {
		case c >= '0' && c <= '9':
			c -= '0'
		case c >= 'a' && c <= 'f':
			c = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			c = c - 'A' + 10
		default:
			return 0, false
		}
		r = r<<4 | rune(c)
	}
	return r, true
}

// isDelimiter reports whether c ends a number or literal.
func isDelimiter(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', ',', ':', '{', '}', '[', ']', '"':
		return true
	}
	return false
}

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
