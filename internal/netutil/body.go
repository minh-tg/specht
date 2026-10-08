package netutil

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// ErrBodyTooLarge reports a response body that exceeded the caller's cap.
var ErrBodyTooLarge = errors.New("response body too large")

// ReadAllLimited reads r to the end but refuses more than limit bytes. It
// reads at most one byte past the limit, and returns ErrBodyTooLarge rather
// than a silently truncated body, so callers never parse half a document.
func ReadAllLimited(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%w: more than %d bytes", ErrBodyTooLarge, limit)
	}
	return data, nil
}

// DecodeJSONLimited decodes one JSON value from r into v, refusing more than
// limit bytes. Use it for responses from endpoints the process does not
// control, where an unbounded decode would let the peer pick our allocation.
func DecodeJSONLimited(r io.Reader, limit int64, v any) error {
	data, err := ReadAllLimited(r, limit)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}
