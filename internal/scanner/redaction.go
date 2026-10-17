package scanner

import (
	"encoding/json"
	"errors"
	"unicode/utf8"
)

// RawEvidenceCap is the most redacted raw output, in bytes, that a report keeps
// for the scanners that cap it (Trivy, Semgrep and Checkov). Output above it is
// cut to this many leading bytes by CapRawEvidence.
const RawEvidenceCap = 64 << 10

// cappedEvidence is the stored form of raw output cut to RawEvidenceCap.
type cappedEvidence struct {
	Truncated     bool   `json:"truncated"`
	OriginalBytes int    `json:"original_bytes"`
	Prefix        string `json:"prefix"`
}

// CapRawEvidence returns the redacted raw output a report stores. Output of up
// to RawEvidenceCap bytes comes back unchanged. A larger output keeps its first
// RawEvidenceCap bytes, cut back to a UTF-8 boundary, in the form
// {"truncated":true,"original_bytes":N,"prefix":"..."}. N is originalBytes, the
// size of the raw output before redaction.
//
// The stored value stays one JSON document because raw_data is a jsonb column:
// a byte cut through a document is not valid JSON, so the cut text is a string
// inside the wrapper. Callers redact before they cap, so the prefix never holds
// a redacted value.
func CapRawEvidence(redacted []byte, originalBytes int) []byte {
	if len(redacted) <= RawEvidenceCap {
		return redacted
	}
	cut := RawEvidenceCap
	for cut > 0 && !utf8.RuneStart(redacted[cut]) {
		cut--
	}
	// Marshal cannot fail: the wrapper holds only a bool, an int and a string.
	out, _ := json.Marshal(cappedEvidence{Truncated: true, OriginalBytes: originalBytes, Prefix: string(redacted[:cut])})
	return out
}

// RedactionFailedEvidence is the JSON ingest stores as a report's raw evidence
// when the scanner's redaction hook cannot process it. Evidence that was not
// redacted is never stored: a document the hook cannot read may still hold a
// credential, so the stored form says that redaction failed and nothing else.
const RedactionFailedEvidence = `{"redaction":"failed"}`

// ErrRedactionFailed is returned by a Redactor that could not decode its input
// or build the redacted form.
var ErrRedactionFailed = errors.New("redaction failed")

// Redactor is implemented by scanners whose raw evidence holds material that
// must not be stored, such as the secret a Gitleaks finding matched. Ingest
// stores RedactRaw's output in place of the report bytes. An error means the
// bytes could not be redacted; the caller then stores RedactionFailedEvidence
// and never the input.
type Redactor interface {
	RedactRaw(data []byte) ([]byte, error)
}
