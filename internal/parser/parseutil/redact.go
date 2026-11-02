package parseutil

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"

	"github.com/minh-tg/specht/internal/scanner"
)

// RedactedMarker replaces the content of a key that RedactRawJSON redacts.
const RedactedMarker = "[REDACTED]"

// Credential rules match on a normalized key: lowercased, with "-" and "_"
// removed, so x-api-key, X_API_KEY and apiKey all read as "xapikey" and
// "apikey". credentialFragments match by name: a key whose normalized name
// contains one of them holds a credential (db_password, auth_token,
// Authorization, ssh_private_key, credentials). credentialSuffixes match the
// end of the name only, for short words that would otherwise hit unrelated keys
// (cookie_consent is left alone, set-cookie and db_pwd are not).
// credentialKeys match the whole name. RedactRawJSON applies all three to every
// scanner, on top of the keys a parser passes. Gitleaks does not use them: it
// matches its own keys (Secret and Match) with RedactKeys.
var (
	credentialKeys      = []string{"accesskey"}
	credentialFragments = []string{"password", "passwd", "passphrase", "secret", "token", "apikey", "privatekey", "credential", "authorization"}
	credentialSuffixes  = []string{"pwd", "cookie", "cookies"}
)

// RedactRawJSON is the RedactRaw of a scanner whose evidence is one JSON
// document. It decodes data, replaces the content of every key in keys and of
// every credential-named key (see isCredentialKey) with RedactedMarker (see
// RedactKeys and redactCredentialFragments), encodes the document again and caps
// the result at scanner.RawEvidenceCap (see scanner.CapRawEvidence). Data it
// cannot decode is an error wrapping scanner.ErrRedactionFailed, and no output
// comes back, because the input may still hold a secret.
func RedactRawJSON(name string, data []byte, keys ...string) ([]byte, error) {
	return RedactRawJSONWith(name, data, nil, keys...)
}

// RedactRawJSONWith is RedactRawJSON with a scanner-specific step: extra, when
// not nil, edits the decoded document before the generic rules run, for values
// that sit under neutral keys (Trivy's image environment).
func RedactRawJSONWith(name string, data []byte, extra func(doc any), keys ...string) ([]byte, error) {
	var doc any
	if err := DecodeJSON(data, &doc); err != nil {
		return nil, fmt.Errorf("%w: %s evidence: %w", scanner.ErrRedactionFailed, name, err)
	}
	if extra != nil {
		extra(doc)
	}
	RedactKeys(doc, RedactedMarker, keys...)
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

// redactCredentialFragments replaces the whole content of each credential-named
// key (see isCredentialKey), at any depth, whatever its type: a scalar, an
// object or a list. Nothing under such a key is walked, so
// db_password: [{"value": "..."}] loses the list and its neutral inner keys
// cannot keep the value. The one exception is a list of scanner findings (see
// isFindingList): Trivy's Secrets list stays a list with its RuleID, Title and
// Severity, which the parser reads back for the fingerprint, while the parser's
// Match and Code keys still remove the value.
func redactCredentialFragments(v any, marker string) {
	switch x := v.(type) {
	case map[string]any:
		for k, item := range x {
			if isCredentialKey(k) {
				if list, ok := item.([]any); ok && isFindingList(list) {
					redactCredentialFragments(list, marker)
					continue
				}
				if hasContent(item) {
					x[k] = marker
					continue
				}
			}
			redactCredentialFragments(item, marker)
		}
	case []any:
		for _, item := range x {
			redactCredentialFragments(item, marker)
		}
	}
}

// isFindingList reports whether list is a non-empty list of objects that each
// carry a RuleID, the shape of Trivy's Secrets findings.
func isFindingList(list []any) bool {
	if len(list) == 0 {
		return false
	}
	for _, item := range list {
		obj, ok := item.(map[string]any)
		if !ok {
			return false
		}
		if _, ok := obj["RuleID"]; !ok {
			return false
		}
	}
	return true
}

// normalizeKey lowercases key and removes "-" and "_".
func normalizeKey(key string) string {
	return strings.Map(func(r rune) rune {
		if r == '-' || r == '_' {
			return -1
		}
		return unicode.ToLower(r)
	}, key)
}

// isCredentialKey reports whether key, normalized, equals one of
// credentialKeys, contains one of credentialFragments or ends with one of
// credentialSuffixes.
func isCredentialKey(key string) bool {
	n := normalizeKey(key)
	for _, k := range credentialKeys {
		if n == k {
			return true
		}
	}
	for _, fragment := range credentialFragments {
		if strings.Contains(n, fragment) {
			return true
		}
	}
	for _, suffix := range credentialSuffixes {
		if strings.HasSuffix(n, suffix) {
			return true
		}
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
