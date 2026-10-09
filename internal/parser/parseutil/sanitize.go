package parseutil

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"net/url"
	"path"
	"strings"
	"unicode/utf8"

	"github.com/minh-tg/specht/internal/domain"
)

const (
	// MaxPathLength bounds parsed file path strings.
	MaxPathLength = 1024

	// MaxTitleLength bounds finding titles to protect database and notification payloads.
	MaxTitleLength = 1024

	// MaxDescriptionLength bounds descriptions to protect memory and storage.
	MaxDescriptionLength = 65536 // 64 KB

	// MaxDimensionValueLength bounds dimension values within the PostgreSQL btree limit (2704 bytes).
	MaxDimensionValueLength = 2048

	// MaxFingerprintLength bounds fingerprints so they never exceed the btree index limit.
	MaxFingerprintLength = 512
)

// CleanFilePath sanitizes an untrusted file path or URI emitted by a scanner:
//   - Strips null bytes (\x00) and unprintable control characters
//   - Strips URI schemes such as file://localhost/, file:///, file://, file:
//   - Unescapes URL percent-encoded characters
//   - Normalizes Windows backslashes (\) to forward slashes (/)
//   - Strips Windows drive letter prefix (e.g. C:)
//   - Cleans redundant slashes and "." segments via path.Clean
//   - Neutralizes directory traversal climbing outside repo root ("../")
//   - Bounds length to MaxPathLength
func CleanFilePath(raw string) string {
	if raw == "" {
		return ""
	}

	// Remove null bytes and control chars (except standard whitespace).
	cleaned := strings.Map(func(r rune) rune {
		if r == 0 || (r < 32 && r != '\t' && r != '\n' && r != '\r') {
			return -1
		}
		return r
	}, raw)
	cleaned = strings.TrimSpace(cleaned)
	if cleaned == "" {
		return ""
	}

	// Handle URI schemes: file://localhost/, file:///, file://, file:
	if strings.HasPrefix(cleaned, "file://localhost/") {
		cleaned = strings.TrimPrefix(cleaned, "file://localhost/")
	} else if strings.HasPrefix(cleaned, "file:///") {
		cleaned = strings.TrimPrefix(cleaned, "file:///")
	} else if strings.HasPrefix(cleaned, "file://") {
		cleaned = strings.TrimPrefix(cleaned, "file://")
	} else if strings.HasPrefix(cleaned, "file:") {
		cleaned = strings.TrimPrefix(cleaned, "file:")
	}

	// Unescape URL path encoding if present (e.g. %20).
	if unescaped, err := url.PathUnescape(cleaned); err == nil && unescaped != "" {
		cleaned = unescaped
	}

	// Strip null bytes and control chars (including any unescaped from %00).
	cleaned = strings.Map(func(r rune) rune {
		if r == 0 || (r < 32 && r != '\t' && r != '\n' && r != '\r') {
			return -1
		}
		return r
	}, cleaned)

	// Normalize Windows backslashes to forward slashes.
	cleaned = strings.ReplaceAll(cleaned, "\\", "/")

	// Preserve whether it had a leading slash (like Checkov's "/terraform/main.tf").
	hasLeadingSlash := strings.HasPrefix(cleaned, "/")

	// Strip Windows drive letter prefix (e.g. "C:/foo/bar" -> "foo/bar").
	if len(cleaned) >= 2 && cleaned[1] == ':' && ((cleaned[0] >= 'a' && cleaned[0] <= 'z') || (cleaned[0] >= 'A' && cleaned[0] <= 'Z')) {
		cleaned = strings.TrimPrefix(cleaned[2:], "/")
	}

	// Clean the path to resolve '.' and '..' segments.
	p := path.Clean("/" + cleaned)

	// Neutralize traversal: if path climbed to root, path.Clean("/" + cleaned)
	// ensured no ".." escaped above "/".
	if hasLeadingSlash {
		cleaned = p
	} else {
		cleaned = strings.TrimPrefix(p, "/")
	}

	if cleaned == "." || cleaned == "/" {
		return ""
	}

	return TruncateString(cleaned, MaxPathLength)
}

// SanitizeText strips null bytes and bounds text to maxLen characters.
func SanitizeText(raw string, maxLen int) string {
	if raw == "" {
		return ""
	}
	s := strings.Map(func(r rune) rune {
		if r == 0 {
			return -1
		}
		return r
	}, raw)
	return TruncateString(s, maxLen)
}

// TruncateString truncates a string to maxLen bytes while preserving valid UTF-8.
func TruncateString(s string, maxLen int) string {
	if maxLen <= 0 || len(s) <= maxLen {
		return s
	}
	count := 0
	byteIdx := 0
	for byteIdx < len(s) {
		_, size := utf8.DecodeRuneInString(s[byteIdx:])
		if count+size > maxLen {
			break
		}
		count += size
		byteIdx += size
	}
	return s[:byteIdx]
}

// SafeLine clamps negative line numbers to 0.
func SafeLine(line int) int {
	if line < 0 {
		return 0
	}
	return line
}

// SafeScore validates and clamps a floating point score:
// NaN or Inf becomes 0.0, negative becomes 0.0, max capped at 10.0.
func SafeScore(score float64) float64 {
	if math.IsNaN(score) || math.IsInf(score, 0) || score < 0 {
		return 0.0
	}
	if score > 10.0 {
		return 10.0
	}
	return score
}

// BoundFingerprint ensures a fingerprint does not exceed the PostgreSQL index limit.
// An overlong fingerprint keeps a prefix and appends a SHA-256 of the whole
// input, so two overlong fingerprints that share a prefix stay distinct.
func BoundFingerprint(fp string) string {
	original := fp
	fp = SanitizeText(fp, MaxFingerprintLength*2)
	if len(fp) <= MaxFingerprintLength {
		return fp
	}
	h := sha256.Sum256([]byte(original))
	prefix := TruncateString(fp, MaxFingerprintLength-65)
	return prefix + ":" + hex.EncodeToString(h[:])
}

// HardenFinding applies defensive bounds and sanitization to an untrusted finding:
//   - Strips null bytes across strings
//   - Bounds Title, Description, Location, and Dimensions
//   - Protects Fingerprint against PostgreSQL index row-size overflow
//   - Validates CodeLocation lines (non-negative)
//   - Validates float scores
func HardenFinding(f domain.NormalizedFinding) domain.NormalizedFinding {
	f.Fingerprint = BoundFingerprint(f.Fingerprint)
	f.Title = SanitizeText(f.Title, MaxTitleLength)
	f.Description = SanitizeText(f.Description, MaxDescriptionLength)
	f.Location = SanitizeText(f.Location, MaxPathLength)
	f.Resource = SanitizeText(f.Resource, MaxTitleLength)
	f.Score = SafeScore(f.Score)

	if f.CodeLocation != nil {
		f.CodeLocation.File = CleanFilePath(f.CodeLocation.File)
		f.CodeLocation.StartLine = SafeLine(f.CodeLocation.StartLine)
		f.CodeLocation.EndLine = SafeLine(f.CodeLocation.EndLine)
		if f.CodeLocation.EndLine < f.CodeLocation.StartLine {
			f.CodeLocation.EndLine = f.CodeLocation.StartLine
		}
		f.CodeLocation.StartColumn = SafeLine(f.CodeLocation.StartColumn)
		f.CodeLocation.EndColumn = SafeLine(f.CodeLocation.EndColumn)
		f.CodeLocation.Snippet = SanitizeText(f.CodeLocation.Snippet, 4096)
	}

	if f.CVSS != nil {
		f.CVSS.Score = SafeScore(f.CVSS.Score)
		f.CVSS.Vector = SanitizeText(f.CVSS.Vector, 256)
		f.CVSS.Version = SanitizeText(f.CVSS.Version, 32)
	}

	for i := range f.Dimensions {
		f.Dimensions[i].Key = SanitizeText(f.Dimensions[i].Key, 64)
		f.Dimensions[i].Value = SanitizeText(f.Dimensions[i].Value, MaxDimensionValueLength)
	}

	for i := range f.Aliases {
		f.Aliases[i] = SanitizeText(f.Aliases[i], 256)
	}

	if f.Fix != nil {
		f.Fix.Summary = SanitizeText(f.Fix.Summary, MaxTitleLength)
		f.Fix.URL = SanitizeText(f.Fix.URL, MaxPathLength)
		f.Fix.Description = SanitizeText(f.Fix.Description, MaxDescriptionLength)
	}

	return f
}

// HardenPackage applies defensive bounds to an inventory package reference.
func HardenPackage(pkg domain.PackageRef) domain.PackageRef {
	pkg.Name = SanitizeText(pkg.Name, MaxTitleLength)
	pkg.Version = SanitizeText(pkg.Version, 256)
	pkg.Ecosystem = SanitizeText(pkg.Ecosystem, 128)
	pkg.PURL = SanitizeText(pkg.PURL, MaxPathLength)
	pkg.ManifestPath = CleanFilePath(pkg.ManifestPath)
	return pkg
}
