package domain

import "testing"

func TestEcosystemFromPURL(t *testing.T) {
	for purl, want := range map[string]string{
		"pkg:npm/lodash@4.17.20":                 "npm",
		"pkg:golang/golang.org/x/crypto@v0.57.0": "golang",
		"pkg:NPM/lodash":                         "npm",
		"pkg:npm/%40types/node@20.1.0":           "npm",
		"pkg:npm":                                "",
		"npm/lodash":                             "",
		"":                                       "",
	} {
		if got := EcosystemFromPURL(purl); got != want {
			t.Errorf("EcosystemFromPURL(%q) = %q, want %q", purl, got, want)
		}
	}
}
