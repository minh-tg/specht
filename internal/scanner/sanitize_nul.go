package scanner

import "errors"

// errNULInFieldName is the cause SanitizeNUL reports for a NUL in an object key.
var errNULInFieldName = errors.New("a field name holds a NUL character")

// SanitizeNUL removes the JSON escape for the NUL character (a backslash, then
// u0000) from the strings of a JSON document. PostgreSQL refuses a NUL in a
// text or jsonb value, so a report that carries one, for example a scanner
// quoting a file with an embedded NUL byte, used to fail the whole ingest with
// a generic 422. The decoders drop the character from every string they hand
// to the store; this does the same to the raw evidence, before anything reads
// the document, so the evidence, the parser and the redactor all see one text.
//
// A NUL in an object key is refused with an error that matches
// ErrMalformedReport instead. Dropping it would rename the field, which would
// change what the parser reads and which keys redaction matches.
//
// The input comes back as it is, without a copy, when it holds no NUL escape.
// A document that is not valid JSON is the decoder's to refuse and passes
// through unchanged. A backslash that is itself escaped (a backslash, a
// backslash, then u0000) is not a NUL and is kept.
func SanitizeNUL(data []byte) ([]byte, error) {
	var out []byte // built on the first NUL escape; data[copied:] is not in out yet
	copied := 0
	for i := 0; i < len(data); i++ {
		if data[i] != '"' {
			continue
		}
		hadNUL := false
		i++
		for i < len(data) && data[i] != '"' {
			if data[i] != '\\' {
				i++
				continue
			}
			if isNULEscape(data, i) {
				if out == nil {
					out = make([]byte, 0, len(data))
				}
				out = append(out, data[copied:i]...)
				copied = i + len(nulEscape)
				hadNUL = true
				i += len(nulEscape)
				continue
			}
			i += 2 // a backslash and the character it escapes
		}
		if hadNUL && isKey(data, i) {
			return nil, Malformed("report", errNULInFieldName)
		}
	}
	if out == nil {
		return data, nil
	}
	return append(out, data[copied:]...), nil
}

const nulEscape = `\u0000`

// isNULEscape reports whether data[at:] starts with the NUL escape.
func isNULEscape(data []byte, at int) bool {
	return at+len(nulEscape) <= len(data) && string(data[at:at+len(nulEscape)]) == nulEscape
}
