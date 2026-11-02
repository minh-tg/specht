package parseutil_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/parser/parseutil"
)

// A list of objects under a credential name is replaced whole, because the
// objects hold the value under a neutral key.
func TestRedactRawJSONRedactsListsOfObjectsUnderACredentialName(t *testing.T) {
	data := []byte(`{"db_password":[{"value":"v1"}],"credentials":[{"user":"u","pass":"p"}],` +
		`"a":{"b":{"c":{"d":{"db_password":[{"value":"v5"}]}}}}}`)
	out, err := parseutil.RedactRawJSON("test", data)
	require.NoError(t, err)
	assert.JSONEq(t, `{"db_password":"[REDACTED]","credentials":"[REDACTED]",`+
		`"a":{"b":{"c":{"d":{"db_password":"[REDACTED]"}}}}}`, string(out))
}

// Spellings that differ by case, hyphen or underscore from the rule names match.
func TestRedactRawJSONMatchesNormalizedCredentialKeys(t *testing.T) {
	keys := []string{
		"x-api-key", "X-API-KEY", "apiKey", "API_KEY", "privateKey", "private_key", "ssh_private_key",
		"SSH-Private-Key", "credentials", "Credential", "passphrase", "key-passphrase", "pwd", "db_pwd",
		"cookie", "Set-Cookie", "cookies", "access_key", "access-key", "client_secret",
	}
	doc := map[string]string{"keep": "ok"}
	for _, k := range keys {
		doc[k] = "leak-" + k
	}
	data, err := json.Marshal(doc)
	require.NoError(t, err)

	out, err := parseutil.RedactRawJSON("test", data)
	require.NoError(t, err)

	assert.NotContains(t, string(out), "leak-")
	assert.Contains(t, string(out), `"keep":"ok"`)
}

// These names share letters with a credential word but name something else, so
// the rules leave them alone.
func TestRedactRawJSONLeavesNeutralKeysAlone(t *testing.T) {
	data := []byte(`{"cookie_consent":"yes","cwd":"/src","keyboard":"us","public_key":"pk","key_id":"k1",` +
		`"api_version":"v2","author":"a","path":"/a","private":true,"pass_count":3,"key":"plain"}`)
	out, err := parseutil.RedactRawJSON("test", data)
	require.NoError(t, err)
	assert.JSONEq(t, string(data), string(out))
}

func TestRedactRawJSONWithRunsTheExtraStepBeforeTheGenericRules(t *testing.T) {
	data := []byte(`{"a":"x","password":"p"}`)
	out, err := parseutil.RedactRawJSONWith("test", data, func(doc any) {
		doc.(map[string]any)["a"] = "changed"
	})
	require.NoError(t, err)
	assert.JSONEq(t, `{"a":"changed","password":"[REDACTED]"}`, string(out))
}
