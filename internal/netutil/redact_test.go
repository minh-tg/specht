package netutil

import (
	"errors"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRedactURLKeepsSchemeAndHostOnly(t *testing.T) {
	cases := map[string]string{
		"https://hooks.slack.com/services/T0/B0/SECRET":       "https://hooks.slack.com",
		"https://user:pass@example.com:8443/h?token=SECRET#f": "https://example.com:8443",
		"not a url":        "(unparseable URL)",
		"":                 "(unparseable URL)",
		"/relative/SECRET": "(unparseable URL)",
	}
	for in, want := range cases {
		got := RedactURL(in)
		assert.Equal(t, want, got, in)
		assert.NotContains(t, got, "SECRET")
		assert.NotContains(t, got, "pass")
	}
}

func TestStripURLErrorDropsTheRequestURL(t *testing.T) {
	cause := errors.New("connection refused")
	err := &url.Error{Op: "Post", URL: "https://h.example/SECRET", Err: cause}

	got := StripURLError(err)

	assert.Equal(t, cause, got)
	assert.NotContains(t, got.Error(), "SECRET")
	plain := errors.New("plain")
	assert.Equal(t, plain, StripURLError(plain))
}
