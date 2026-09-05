package scanner

import "github.com/xMinhx/specht/internal/domain"

// NormalizePURL strips qualifiers/subpath from a package URL. It is the
// version-1 purl normalization shared by findings and inventory and lives in
// internal/domain; this forwarding keeps existing scanner-package callers
// compiling during the boundary move.
func NormalizePURL(purl string) string {
	return domain.NormalizePURL(purl)
}

// SplitPURL decomposes a package URL into type, name, and version.
func SplitPURL(purl string) (pkgType, name, version string) {
	return domain.SplitPURL(purl)
}
