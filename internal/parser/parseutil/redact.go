package parseutil

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/minh-tg/specht/internal/scanner"
)

// RedactedMarker replaces the content of a key that RedactRawJSON redacts.
const RedactedMarker = "[REDACTED]"

// credentialKeys are exact key names that hold a credential in any scanner's
// raw output. credentialFragments match by name: a key whose lowercased name
// contains one of them holds a credential too (db_password, auth_token,
// Authorization). RedactRawJSON applies both to every scanner, on top of the
// keys a parser passes. Gitleaks does not use them: it matches its own keys
// (Secret and Match) with RedactKeys.
var (
	credentialKeys      = []string{"secret", "password", "passwd", "token", "api_key", "apikey", "access_key", "private_key", "client_secret"}
	credentialFragments = []string{"password", "passwd", "secret", "token", "api_key", "apikey", "authorization"}
)

// RedactRawJSON is the RedactRaw of a scanner whose evidence is one JSON
// document. It decodes data, replaces the content of every key in keys and of
// every credential key (see credentialKeys) with RedactedMarker (see
// RedactKeys), replaces the scalar content of every key that holds a credential
// fragment (see redactCredentialFragments), encodes the document again and caps
// the result at scanner.RawEvidenceCap (see scanner.CapRawEvidence). Data it
// cannot decode is an error wrapping scanner.ErrRedactionFailed, and no output
// comes back, because the input may still hold a secret.
func RedactRawJSON(name string, data []byte, keys ...string) ([]byte, error) {
	var doc any
	if err := DecodeJSON(data, &doc); err != nil {
		return nil, fmt.Errorf("%w: %s evidence: %w", scanner.ErrRedactionFailed, name, err)
	}
	RedactKeys(doc, RedactedMarker, keys...)
	RedactKeys(doc, RedactedMarker, credentialKeys...)
	redactCredentialFragments(doc, RedactedMarker)
	out, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("%w: %s evidence: %w", scanner.ErrRedactionFailed, name, err)
	}
	return scanner.CapRawEvidence(out, len(data)), nil
}

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

// redactCredentialFragments replaces the content of each key whose lowercased
// name contains a credential fragment, at any depth, when that content is a
// scalar. A list or object under such a key is walked instead of replaced, so
// the keys inside it keep their own rules. Trivy's Secrets list stays a list
// with its RuleID, Title and Severity, which the parser reads back for the
// fingerprint, while the parser's Match and Code keys still remove the value.
// A credential inside such an object under a neutral name, such as
// auth_token: {"value": "..."}, is not redacted.
func redactCredentialFragments(v any, marker string) {
	switch x := v.(type) {
	case map[string]any:
		for k, item := range x {
			if hasCredentialFragment(k) && !isContainer(item) && hasContent(item) {
				x[k] = marker
				continue
			}
			redactCredentialFragments(item, marker)
		}
	case []any:
		for _, item := range x {
			redactCredentialFragments(item, marker)
		}
	}
}

// hasCredentialFragment reports whether key, lowercased, contains one of
// credentialFragments.
func hasCredentialFragment(key string) bool {
	lower := strings.ToLower(key)
	for _, fragment := range credentialFragments {
		if strings.Contains(lower, fragment) {
			return true
		}
	}
	return false
}

func isContainer(v any) bool {
	switch v.(type) {
	case map[string]any, []any:
		return true
	}
	return false
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
