package osvscanner

import (
	"strings"

	"github.com/minh-tg/specht/internal/domain"
)

// purlTypes maps an OSV ecosystem to its package URL type. OSV names the
// ecosystem the way its database does ("Go", "crates.io", "Packagist"), which
// is not the purl type every other SCA adapter keys a package on.
//
// Only ecosystems whose purl is the type, the name and the version are listed.
// Debian, Ubuntu, Alpine and the other distributions are left out: their purl
// needs the distribution as a namespace, and OSV names the source package where
// scanners name the binary package, so a purl built here would not match.
// Maven and Packagist are handled in purlName, and the rest of OSV's
// ecosystems (GitHub Actions, SwiftURL, Hackage, Julia and so on) are left out
// because they are not used by lockfiles that osv-scanner reads.
var purlTypes = map[string]string{
	"go":        "golang",
	"npm":       "npm",
	"pypi":      "pypi",
	"crates.io": "cargo",
	"maven":     "maven",
	"rubygems":  "gem",
	"nuget":     "nuget",
	"packagist": "composer",
	"hex":       "hex",
	"pub":       "pub",
	"cran":      "cran",
}

// purlName spells a package name the way its purl type does, or says it cannot.
// A Maven name is group:artifact in OSV and group/artifact in a purl. A PyPI
// name is lowercased with underscores as dashes, as the purl spec asks and as
// Trivy and Grype write it. An npm scope marker is percent-encoded, so the
// purl reads pkg:npm/%40angular/core, as in the purls OSV itself writes.
func purlName(purlType, name string) (string, bool) {
	if name == "" {
		return "", false
	}
	switch purlType {
	case "maven":
		group, artifact, ok := strings.Cut(name, ":")
		if !ok || group == "" || artifact == "" {
			return "", false
		}
		return group + "/" + artifact, true
	case "pypi":
		return strings.ReplaceAll(strings.ToLower(name), "_", "-"), true
	case "npm":
		return strings.ReplaceAll(name, "@", "%40"), true
	}
	return name, true
}

// purl is the package URL of the scanned package at its installed version, the
// purl every other SCA adapter keys a package and a finding on. It is the same
// string for the inventory entry and for each finding of the package, so the
// two meet. The order:
//
//  1. The purl OSV-Scanner wrote for the package.
//  2. A purl built from the ecosystem (see purlTypes), name and version.
//  3. For an ecosystem not in purlTypes, the purl of the advisory's affected
//     package (advisory) with the installed version added.
//  4. A generic purl: the ecosystem is unknown, so the type says so instead of
//     naming a type that does not exist.
//
// The advisory purl comes after the ecosystem so that the result does not
// depend on which vulnerability's advisory the caller has at hand.
func (p osvPkg) purl(advisory string) string {
	if p.PURL != "" {
		return domain.NormalizePURL(p.PURL)
	}
	base, _, _ := strings.Cut(p.Ecosystem, ":")
	if purlType, ok := purlTypes[strings.ToLower(strings.TrimSpace(base))]; ok {
		if name, ok := purlName(purlType, p.Name); ok {
			return withVersion("pkg:"+purlType+"/"+name, p.Version)
		}
	}
	if advisory = domain.NormalizePURL(advisory); strings.HasPrefix(advisory, "pkg:") {
		_, _, version := domain.SplitPURL(advisory)
		return withVersion(strings.TrimSuffix(advisory, "@"+version), p.Version)
	}
	return withVersion("pkg:generic/"+p.Name, p.Version)
}

// withVersion appends @version to an unversioned purl. Without a version the
// purl is returned as it is.
func withVersion(purl, version string) string {
	if version == "" {
		return purl
	}
	return purl + "@" + version
}
