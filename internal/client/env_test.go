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

func TestCheckAPIURL(t *testing.T) {
	env := func(values map[string]string) func(string) string {
		return func(name string) string { return values[name] }
	}
	optOut := env(map[string]string{EnvAllowInsecureHTTP: "1"})
	cases := []struct {
		name    string
		url     string
		env     func(string) string
		wantErr bool
	}{
		{"https to any host", "https://specht.example.com", env(nil), false},
		{"https is case-insensitive", "HTTPS://specht.example.com", env(nil), false},
		{"http to localhost", "http://localhost:8080", env(nil), false},
		{"http to a localhost subdomain", "http://api.localhost:8080", env(nil), false},
		{"http to 127.0.0.1", "http://127.0.0.1:8080", env(nil), false},
		{"http to another 127 address", "http://127.1.2.3", env(nil), false},
		{"http to IPv6 loopback", "http://[::1]:8080", env(nil), false},
		{"http to a private address", "http://10.0.0.5:8080", env(nil), true},
		{"http to a public host", "http://specht.example.com", env(nil), true},
		{"http to a name that starts like loopback", "http://127.0.0.1.evil.example", env(nil), true},
		{"http with a loopback user name", "http://127.0.0.1@evil.example/", env(nil), true},
		{"http to a host that only ends in localhost", "http://notlocalhost", env(nil), true},
		{"http to a private address with the opt-out", "http://10.0.0.5:8080", optOut, false},
		{"opt-out accepts true", "http://10.0.0.5", env(map[string]string{EnvAllowInsecureHTTP: "TRUE"}), false},
		{"opt-out ignores other values", "http://10.0.0.5", env(map[string]string{EnvAllowInsecureHTTP: "yes"}), true},
		{"no scheme", "specht.example.com", env(nil), true},
		{"host and port without a scheme", "localhost:8080", env(nil), true},
		{"unsupported scheme", "ftp://specht.example.com", env(nil), true},
		{"empty", "", env(nil), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckAPIURL(tc.url, tc.env)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCheckAPIURLErrorNamesTheHostAndTheOptOut(t *testing.T) {
	err := CheckAPIURL("http://user:secret@10.0.0.5:8080/x", func(string) string { return "" })
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "10.0.0.5:8080")
		assert.Contains(t, err.Error(), EnvAllowInsecureHTTP)
		assert.NotContains(t, err.Error(), "secret")
	}
}

func TestResolveAPIURL(t *testing.T) {
	none := func(string) string { return "" }
	got, err := ResolveAPIURL(none)
	assert.NoError(t, err)
	assert.Equal(t, DefaultAPIURL, got)

	_, err = ResolveAPIURL(func(name string) string {
		if name == "SPECHT_API_URL" {
			return "http://10.0.0.5"
		}
		return ""
	})
	assert.Error(t, err, "the alias is checked like the plain name")
}
