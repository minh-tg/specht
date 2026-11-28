package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// A sign-in plants the resume cookie only when the request could not have come from a form on
// another site: a JSON content type needs a preflight the server never grants, and a browser marks a
// cross-site request itself.
func TestIsSameSiteJSONRequest(t *testing.T) {
	cases := map[string]struct {
		contentType string
		fetchSite   string
		want        bool
	}{
		"the SPA":                      {"application/json", "same-origin", true},
		"json with a charset":          {"application/json; charset=utf-8", "", true},
		"a client with no fetch site":  {"application/json", "", true},
		"a plain-text form post":       {"text/plain", "cross-site", false},
		"a plain-text post, old agent": {"text/plain;charset=UTF-8", "", false},
		"no content type":              {"", "", false},
		"a url-encoded form":           {"application/x-www-form-urlencoded", "", false},
		"json claiming cross-site":     {"application/json", "cross-site", false},
		"a bad content type":           {"application/json;;;", "", false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
			if tc.contentType != "" {
				r.Header.Set("Content-Type", tc.contentType)
			}
			if tc.fetchSite != "" {
				r.Header.Set("Sec-Fetch-Site", tc.fetchSite)
			}
			assert.Equal(t, tc.want, isSameSiteJSONRequest(r))
		})
	}
}
