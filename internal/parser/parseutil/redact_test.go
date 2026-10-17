package parseutil_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/parser/parseutil"
)

func TestRedactKeysMatchesWithoutRegardToCaseAtAnyDepth(t *testing.T) {
	doc := map[string]any{
		"Secret": "a",
		"sEcReT": "b",
		"keep":   "c",
		"inner":  map[string]any{"SECRET": "d", "list": []any{map[string]any{"secret": "e"}, "plain"}},
	}
	parseutil.RedactKeys(doc, "[X]", "secret")
	assert.Equal(t, map[string]any{
		"Secret": "[X]",
		"sEcReT": "[X]",
		"keep":   "c",
		"inner":  map[string]any{"SECRET": "[X]", "list": []any{map[string]any{"secret": "[X]"}, "plain"}},
	}, doc)
}

func TestRedactKeysLeavesEmptyValuesAlone(t *testing.T) {
	doc := map[string]any{"secret": "", "Match": nil, "match": []any{}, "SECRET": map[string]any{}, "secret2": "x"}
	parseutil.RedactKeys(doc, "[X]", "secret", "match")
	assert.Equal(t, map[string]any{"secret": "", "Match": nil, "match": []any{}, "SECRET": map[string]any{}, "secret2": "x"}, doc)
}

func TestRedactRawJSONRedactsCredentialKeysAtDepthOneAndFive(t *testing.T) {
	data := []byte(`{"password":"p1","token":"t1","api_key":"k1","keep":"ok",` +
		`"a":{"b":{"c":{"d":{"password":"p5","token":"t5","api_key":"k5"}}}}}`)
	out, err := parseutil.RedactRawJSON("test", data)
	require.NoError(t, err)
	assert.JSONEq(t, `{"password":"[REDACTED]","token":"[REDACTED]","api_key":"[REDACTED]","keep":"ok",`+
		`"a":{"b":{"c":{"d":{"password":"[REDACTED]","token":"[REDACTED]","api_key":"[REDACTED]"}}}}}`, string(out))
}

// TestRedactRawJSONRedactsCredentialNameFragmentsAtAnyDepth covers keys that
// hold a credential only by name fragment. tokenizer_version matches the token
// fragment too: it is a known false positive, and it stays redacted.
func TestRedactRawJSONRedactsCredentialNameFragmentsAtAnyDepth(t *testing.T) {
	data := []byte(`{"db_password":"dbp1","auth_token":"at1","Authorization":"az1","client_secret":"cs1","tokenizer_version":"v1","keep":"ok",` +
		`"a":{"b":{"c":{"d":{"DB_PASSWORD":"dbp5","auth_token":"at5","Authorization":"az5","client_secret":"cs5","tokenizer_version":"v5"}}}}}`)
	out, err := parseutil.RedactRawJSON("test", data)
	require.NoError(t, err)
	assert.JSONEq(t, `{"db_password":"[REDACTED]","auth_token":"[REDACTED]","Authorization":"[REDACTED]","client_secret":"[REDACTED]","tokenizer_version":"[REDACTED]","keep":"ok",`+
		`"a":{"b":{"c":{"d":{"DB_PASSWORD":"[REDACTED]","auth_token":"[REDACTED]","Authorization":"[REDACTED]","client_secret":"[REDACTED]","tokenizer_version":"[REDACTED]"}}}}}`, string(out))
}

// TestRedactRawJSONRedactsAnObjectUnderACredentialName pins that an object under
// a credential fragment is replaced whole. Its inner value has a neutral name,
// so a walk into the object would store it.
func TestRedactRawJSONRedactsAnObjectUnderACredentialName(t *testing.T) {
	data := []byte(`{"db_password":{"value":"x"},"keep":{"value":"ok"},` +
		`"a":{"b":{"c":{"d":{"auth_token":{"value":"y","nested":{"z":"w"}}}}}}}`)
	out, err := parseutil.RedactRawJSON("test", data)
	require.NoError(t, err)
	assert.JSONEq(t, `{"db_password":"[REDACTED]","keep":{"value":"ok"},`+
		`"a":{"b":{"c":{"d":{"auth_token":"[REDACTED]"}}}}}`, string(out))
}

// TestRedactRawJSONKeepsAListUnderACredentialName pins that a list under a
// credential fragment keeps its shape. The objects inside keep RuleID and
// StartLine, and only the parser's own Match key is replaced.
func TestRedactRawJSONKeepsAListUnderACredentialName(t *testing.T) {
	data := []byte(`{"Secrets":[{"RuleID":"aws-access-key-id","StartLine":3,"Match":"AKIA-VALUE"}]}`)
	out, err := parseutil.RedactRawJSON("test", data, "Match")
	require.NoError(t, err)
	assert.JSONEq(t, `{"Secrets":[{"RuleID":"aws-access-key-id","StartLine":3,"Match":"[REDACTED]"}]}`, string(out))
}

func TestRedactRawJSONRedactsParserKeysInAdditionToCredentialKeys(t *testing.T) {
	data := []byte(`{"snippet":"s","Match":"m","password":"p","keep":"ok"}`)
	out, err := parseutil.RedactRawJSON("test", data, "snippet", "Match")
	require.NoError(t, err)
	assert.JSONEq(t, `{"snippet":"[REDACTED]","Match":"[REDACTED]","password":"[REDACTED]","keep":"ok"}`, string(out))
}

func TestRedactKeysRedactsNonStringContent(t *testing.T) {
	doc := map[string]any{"secret": []any{"a"}, "match": 12345.0, "request": map[string]any{"body": "b"}}
	parseutil.RedactKeys(doc, "[X]", "secret", "match", "request")
	assert.Equal(t, map[string]any{"secret": "[X]", "match": "[X]", "request": "[X]"}, doc)
}
