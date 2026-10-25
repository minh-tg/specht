package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEnvAPIURLAndKeyReadBothNames(t *testing.T) {
	env := func(values map[string]string) func(string) string {
		return func(name string) string { return values[name] }
	}

	assert.Empty(t, EnvAPIURL(env(nil)))
	assert.Empty(t, EnvAPIKey(env(nil)))

	alias := env(map[string]string{"SPECHT_API_URL": "https://alias", "SPECHT_API_KEY": "alias-key"})
	assert.Equal(t, "https://alias", EnvAPIURL(alias))
	assert.Equal(t, "alias-key", EnvAPIKey(alias))

	both := env(map[string]string{
		"API_URL": "https://plain", "SPECHT_API_URL": "https://alias",
		"API_KEY": "plain-key", "SPECHT_API_KEY": "alias-key",
	})
	assert.Equal(t, "https://plain", EnvAPIURL(both), "the unprefixed name wins")
	assert.Equal(t, "plain-key", EnvAPIKey(both), "the unprefixed name wins")
}
