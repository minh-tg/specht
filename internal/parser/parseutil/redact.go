package parseutil

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

// DecodeJSON decodes data, which must hold exactly one JSON value, into v. It
// keeps numbers as json.Number, so a number that does not fit a float64 (such as
// 1e400) in a field the caller does not read cannot make the decode fail. A
// redaction hook decodes with it: a decode that fails where the typed parser's
// succeeded would leave nothing to redact.
func DecodeJSON(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("unexpected data after the JSON value")
	}
	return nil
}

// RedactKeys replaces, in a decoded JSON value, the content of every key that
// matches one of keys with marker. It matches without regard to case, because
// encoding/json fills struct fields from keys of any case, so a parser reads
// (and may hash) a "secret" key that a redactor looking for "Secret" would
// leave in the stored evidence. It walks objects and lists at any depth.
//
// A key with no content (null, an empty string, list or object) is left as it
// is, so the marker only appears where something was removed.
func RedactKeys(v any, marker string, keys ...string) {
	switch x := v.(type) {
	case map[string]any:
		for k, item := range x {
			if matchesKey(k, keys) {
				if hasContent(item) {
					x[k] = marker
				}
				continue
			}
			RedactKeys(item, marker, keys...)
		}
	case []any:
		for _, item := range x {
			RedactKeys(item, marker, keys...)
		}
	}
}

func matchesKey(key string, keys []string) bool {
	for _, k := range keys {
		if strings.EqualFold(key, k) {
			return true
		}
	}
	return false
}

func hasContent(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case string:
		return x != ""
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	}
	return true
}
