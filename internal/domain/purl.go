package domain

import (
	"net/url"
	"strings"
)

// NormalizePURL strips the qualifiers (?...) and subpath (#...) sections from a
// package URL while keeping its type, namespace, name, and version components.
//
// Scan reports frequently qualify purls with build-specific context such as
// arch or distro (e.g. pkg:apk/alpine/libcrypto3@3.3.2-r0?arch=aarch64). The
// normalized form is the identity used to match findings against the package
// inventory, so two scans of the same package on different architectures still
// reference the same purl@version.
//
// Inputs that are not purls are returned unchanged.
func NormalizePURL(purl string) string {
	if !strings.HasPrefix(purl, "pkg:") {
		return purl
	}
	if i := strings.IndexAny(purl, "?#"); i >= 0 {
		purl = purl[:i]
	}
	return purl
}

// SplitPURL decomposes a package URL into its type, name, and version
// components. Qualifiers and subpath are ignored; the name retains any
// namespace segments (e.g. pkg:maven/org.apache.logging.log4j/log4j-core@2.17.0
// yields name "org.apache.logging.log4j/log4j-core"). Inputs that are not
// purls, or purls without a version, yield empty components for the missing
// parts.
func SplitPURL(purl string) (pkgType, name, version string) {
	purl = NormalizePURL(purl)
	rest := strings.TrimPrefix(purl, "pkg:")
	if rest == purl {
		return "", "", ""
	}
	typeEnd := strings.IndexByte(rest, '/')
	if typeEnd < 0 {
		return rest, "", ""
	}
	pkgType = rest[:typeEnd]
	nameWithVersion := rest[typeEnd+1:]
	if at := strings.LastIndexByte(nameWithVersion, '@'); at > strings.LastIndexByte(nameWithVersion, '/') {
		return pkgType, nameWithVersion[:at], nameWithVersion[at+1:]
	}
	return pkgType, nameWithVersion, ""
}

// EcosystemFromPURL is the ecosystem a package URL names (pkg:npm/lodash@1.0 is
// npm), or empty when the value is not a package URL.
func EcosystemFromPURL(purl string) string {
	rest, ok := strings.CutPrefix(purl, "pkg:")
	if !ok {
		return ""
	}
	kind, _, found := strings.Cut(rest, "/")
	if !found {
		return ""
	}
	return strings.ToLower(kind)
}

// PackageFromPURL is the package name and version a package URL names:
// pkg:npm/%40types/node@20.1.0?arch=x is @types/node and 20.1.0, and a Go module
// keeps its whole path. Both are empty when the value is not a package URL.
func PackageFromPURL(purl string) (name, version string) {
	if !strings.HasPrefix(purl, "pkg:") {
		return "", ""
	}
	_, rest, found := strings.Cut(NormalizePURL(purl), "/")
	if !found {
		return "", ""
	}
	if at := strings.LastIndex(rest, "@"); at > 0 {
		rest, version = rest[:at], rest[at+1:]
	}
	if unescaped, err := url.PathUnescape(rest); err == nil {
		rest = unescaped
	}
	return rest, version
}
