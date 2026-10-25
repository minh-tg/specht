package osvscanner_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/domain"
	"github.com/minh-tg/specht/internal/parser/osvscanner"
)

func purlOf(f domain.NormalizedFinding) string {
	for _, d := range f.Dimensions {
		if d.Key == "purl" {
			return d.Value
		}
	}
	return ""
}

// A finding and the inventory entry of its package are one purl, for every
// fixture: the inventory is matched to findings by it.
func TestInventoryPURLsMeetTheFindings(t *testing.T) {
	for _, file := range []string{"testdata/go-scan.json", "testdata/two-lockfiles.json", "testdata/go-full.json"} {
		t.Run(file, func(t *testing.T) {
			data, err := os.ReadFile(file)
			require.NoError(t, err)
			rep, err := osvscanner.NewScanner().Parse(context.Background(), data)
			require.NoError(t, err)
			require.NotEmpty(t, rep.Findings)

			inventory := map[string]bool{}
			for _, p := range rep.Packages {
				inventory[p.PURL] = true
				assert.Contains(t, p.PURL, "@"+p.Version, "the inventory purl carries the installed version")
			}
			for _, f := range rep.Findings {
				assert.True(t, inventory[purlOf(f)], "no inventory entry has the purl %s of finding %s", purlOf(f), f.Fingerprint)
			}
		})
	}
}

func TestAGoPackageWithoutAPURLIsAGolangPURLWithItsVersion(t *testing.T) {
	data, err := os.ReadFile("testdata/go-scan.json")
	require.NoError(t, err)
	rep, err := osvscanner.NewScanner().Parse(context.Background(), data)
	require.NoError(t, err)

	require.Len(t, rep.Packages, 1)
	assert.Equal(t, "pkg:golang/github.com/gogo/protobuf@v1.3.1", rep.Packages[0].PURL,
		"the inventory purl was pkg:go/github.com/gogo/protobuf, a type that does not exist, with no version")
	require.Len(t, rep.Findings, 1)
	assert.Equal(t, rep.Packages[0].PURL, purlOf(rep.Findings[0]))
}

func TestAnNpmPackageWithoutAPURLKeepsItsVersionInTheInventory(t *testing.T) {
	data, err := os.ReadFile("testdata/two-lockfiles.json")
	require.NoError(t, err)
	rep, err := osvscanner.NewScanner().Parse(context.Background(), data)
	require.NoError(t, err)

	var got []string
	for _, p := range rep.Packages {
		got = append(got, p.PURL)
	}
	assert.Equal(t, []string{"pkg:npm/lodash@4.17.20", "pkg:npm/lodash@4.17.15"}, got)
}

// With neither a package purl nor an advisory to ask, the purl is built from the
// ecosystem alone, for the inventory and for the finding alike.
func TestPURLTypeFollowsTheEcosystem(t *testing.T) {
	cases := []struct {
		ecosystem, name, version, want string
	}{
		{"Go", "github.com/acme/lib", "1.2.0", "pkg:golang/github.com/acme/lib@v1.2.0"},
		{"PyPI", "Flask_Login", "0.6.3", "pkg:pypi/flask-login@0.6.3"},
		{"npm", "@angular/core", "17.0.0", "pkg:npm/%40angular/core@17.0.0"},
		{"npm", "lodash", "4.17.20", "pkg:npm/lodash@4.17.20"},
		{"crates.io", "serde", "1.0.1", "pkg:cargo/serde@1.0.1"},
		{"Maven", "org.apache.logging.log4j:log4j-core", "2.14.1", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},
		{"RubyGems", "rails", "6.0.0", "pkg:gem/rails@6.0.0"},
		{"NuGet", "Newtonsoft.Json", "12.0.1", "pkg:nuget/Newtonsoft.Json@12.0.1"},
		{"Packagist", "symfony/http-kernel", "5.4.0", "pkg:composer/symfony/http-kernel@5.4.0"},
		{"Hex", "plug", "1.0.0", "pkg:hex/plug@1.0.0"},
		{"Pub", "http", "0.13.0", "pkg:pub/http@0.13.0"},
		{"CRAN", "dplyr", "1.0.0", "pkg:cran/dplyr@1.0.0"},
		// A suffix after the colon names a registry or release, not another type.
		{"Maven:https://repo.example.com/maven", "g:a", "1", "pkg:maven/g/a@1"},
		// Distributions need a namespace and the binary package name: not mapped.
		{"Debian:12", "openssl", "3.0.11-1", "pkg:generic/openssl@3.0.11-1"},
		{"Alpine:v3.20", "busybox", "1.36.1-r0", "pkg:generic/busybox@1.36.1-r0"},
		// A Maven name that is not group:artifact cannot be a Maven purl.
		{"Maven", "log4j", "1.2.17", "pkg:generic/log4j@1.2.17"},
	}
	for _, tc := range cases {
		t.Run(tc.ecosystem+"/"+tc.name, func(t *testing.T) {
			data := []byte(`{"results":[{"source":{"path":"lock","type":"lockfile"},"packages":[{"package":{"name":"` + tc.name +
				`","version":"` + tc.version + `","ecosystem":"` + tc.ecosystem + `"},"vulnerabilities":[{"id":"V-1"}]}]}]}`)
			rep, err := osvscanner.NewScanner().Parse(context.Background(), data)
			require.NoError(t, err)
			require.Len(t, rep.Packages, 1)
			require.Len(t, rep.Findings, 1)
			assert.Equal(t, tc.want, rep.Packages[0].PURL)
			assert.Equal(t, tc.want, purlOf(rep.Findings[0]))
			assert.Equal(t, "V-1:"+tc.want, rep.Findings[0].Fingerprint)
		})
	}
}

// For an ecosystem with no purl type here, the advisory's purl supplies the
// type and name, and the installed version is added.
func TestAnUnmappedEcosystemTakesTheAdvisoryPURL(t *testing.T) {
	data := []byte(`{"results":[{"source":{"path":"lock","type":"lockfile"},"packages":[{"package":{"name":"openssl","version":"3.0.11-1","ecosystem":"Debian:12"},
		"vulnerabilities":[{"id":"V-1","affected":[{"package":{"name":"openssl","ecosystem":"Debian:12","purl":"pkg:deb/debian/openssl?distro=debian-12"}}]}]}]}]}`)
	rep, err := osvscanner.NewScanner().Parse(context.Background(), data)
	require.NoError(t, err)
	require.Len(t, rep.Packages, 1)
	assert.Equal(t, "pkg:deb/debian/openssl@3.0.11-1", rep.Packages[0].PURL)
	assert.Equal(t, rep.Packages[0].PURL, purlOf(rep.Findings[0]))
}

func TestAPackagePURLIsKeptWhateverTheEcosystem(t *testing.T) {
	data := []byte(`{"results":[{"source":{"path":"lock","type":"lockfile"},"packages":[{"package":{"name":"x","version":"1","ecosystem":"Go","purl":"pkg:golang/x@v1?type=mod"},
		"vulnerabilities":[{"id":"V-1"}]}]}]}`)
	rep, err := osvscanner.NewScanner().Parse(context.Background(), data)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(rep.Packages[0].PURL, "pkg:golang/x@"), rep.Packages[0].PURL)
	assert.NotContains(t, rep.Packages[0].PURL, "?", "qualifiers are dropped")
}
