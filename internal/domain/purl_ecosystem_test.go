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

func TestPackageFromPURL(t *testing.T) {
	for _, tc := range []struct{ purl, name, version string }{
		{"pkg:npm/lodash@4.17.20", "lodash", "4.17.20"},
		{"pkg:npm/%40types/node@20.1.0", "@types/node", "20.1.0"},
		{"pkg:golang/golang.org/x/crypto@v0.57.0", "golang.org/x/crypto", "v0.57.0"},
		{"pkg:apk/alpine/libcrypto3@3.3.2-r0?arch=aarch64", "alpine/libcrypto3", "3.3.2-r0"},
		{"pkg:npm/lodash", "lodash", ""},
		{"pkg:npm", "", ""},
		{"lodash", "", ""},
		{"", "", ""},
	} {
		name, version := PackageFromPURL(tc.purl)
		if name != tc.name || version != tc.version {
			t.Errorf("PackageFromPURL(%q) = %q, %q, want %q, %q", tc.purl, name, version, tc.name, tc.version)
		}
	}
}
