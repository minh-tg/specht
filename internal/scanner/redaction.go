package scanner

import "errors"

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
