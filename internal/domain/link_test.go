package domain

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLinkURLProblem(t *testing.T) {
	for s, ok := range map[string]bool{
		"":                                   true,
		"https://github.com/acme/shop":       true,
		"http://git.internal:8080/acme/shop": true,
		"https://gitlab.example.com/acme/shop/-/jobs/77":                true,
		"https://gitlab-ci-token:glcbt-secret@gitlab.com/acme/shop.git": false,
		"https://user@git.example.org/acme":                             false,
		"javascript:alert(1)":                                           false,
		"HTTPS://github.com/acme":                                       false,
		"/acme/shop":                                                    false,
		"https:///acme":                                                 false,
		"https://github.com/acme shop":                                  false,
		"https://github.com/acme\nshop":                                 false,
		"ftp://example.com/run":                                         false,
		"https://e.com/" + strings.Repeat("p", 2048):                    false,
	} {
		problem := LinkURLProblem(s)
		assert.Equal(t, ok, problem == "", "%q: %s", s, problem)
		assert.NotContains(t, problem, "glcbt-secret")
	}
}
