// Package domain defines the core, engine-neutral domain vocabulary of
// Specht: the normalized scan report/finding model, canonical dimension
// keys, purl normalization, and the reachability hint shape. Packages inside
// internal/domain must not import sqlc, pgtype, HTTP, or scanner packages;
// the persistence adapter (internal/repo) and the HTTP layer translate
// between this vocabulary and their own representations.
//
// The scanner package is the plugin seam and returns *domain.NormalizedReport
// from Parse; producers and core consumers import this package directly.
package domain

import "strings"

// ScanType classifies what kind of artifact a scan covered.
type ScanType string

const (
	ScanTypeImage      ScanType = "image"
	ScanTypeFilesystem ScanType = "filesystem"
	ScanTypeRepository ScanType = "repository"
	ScanTypeIaC        ScanType = "iac"
	ScanTypeSBOM       ScanType = "sbom"
	ScanTypeLockfile   ScanType = "lockfile"
	ScanTypeDAST       ScanType = "dast"
)

// Severity is the normalized severity scale used across scanners. The int
// values are ordered so severity comparisons (>, >=) work across the whole
// pipeline.
type Severity int

const (
	SeverityUnknown  Severity = 0
	SeverityLow      Severity = 1
	SeverityMedium   Severity = 2
	SeverityHigh     Severity = 3
	SeverityCritical Severity = 4
)

// ContractVersion is the version of the normalized report contract a
// producer (scanner parser) implements.
type ContractVersion uint16

// FingerprintVersion is the version of the finding fingerprint algorithm a
// finding's fingerprint was produced with. Version 1 fingerprints remain
// stable so existing rows and waivers do not silently fork.
type FingerprintVersion uint16

// ScanCompleteness describes how much of a scan target the report covers.
type ScanCompleteness string

const (
	CompletenessUnknown  ScanCompleteness = "unknown"
	CompletenessPartial  ScanCompleteness = "partial"
	CompletenessComplete ScanCompleteness = "complete"
)

// PackageRef identifies a single package found in a scan, whether or not it
// has an associated finding. The PURL is normalized (qualifiers and subpath
// stripped) so inventory lookups can be matched by name and version; note
// that some scanners (e.g. osv-scanner) emit finding purls without a version,
// so callers should not assume every purl carries one.
type PackageRef struct {
	PURL         string
	Ecosystem    string
	Name         string
	Version      string
	ManifestPath string
}

// TargetInfo identifies the scan target (repository, image, filesystem...).
type TargetInfo struct {
	Kind       string
	Identifier string
}

// ArtifactInfo identifies a specific artifact of the target when the scanner
// reports one.
type ArtifactInfo struct {
	Kind       string
	Identifier string
	// Digest is the content digest (e.g. sha256:…) when the scanner
	// reports one. Tags are mutable and never identity; digests are.
	Digest   string
	Metadata map[string]any
}

// NormalizedFinding is one scanner-detected issue in the normalized model.
// Fingerprint must be stable across scans of the same issue (see the
// per-kind fingerprint formulas) and Dimensions carries the structured
// key/value pairs used for waiver matching and display.
type NormalizedFinding struct {
	Fingerprint  string
	FindingKind  string
	Title        string
	Description  string
	Severity     Severity
	Score        float64
	Location     string
	Resource     string
	Aliases      []string
	Reachability *ReachabilityHint
	CVSS         *CVSSInfo
	Fix          *FixInfo
	CodeLocation *CodeLocation
	Dimensions   []Dimension
	// Extensions carries producer payloads that do not fit a canonical
	// dimension or typed field. The Postgres occurrence mapper preserves
	// payloads under their source namespace (extension keys are namespaced
	// by producer, e.g. "trivy.cwe_ids") and reserves the "specht" namespace
	// for canonical CVSS/fix/location/resource data. Extension keys never
	// become identity or gate inputs.
	Extensions map[string]any
}

// CVSSInfo is a parsed CVSS vector and its score.
type CVSSInfo struct {
	Version string
	Vector  string
	Score   float64
}

// FixInfo describes the remediation for a finding when known.
type FixInfo struct {
	Summary     string
	Description string
	URL         string
	Diff        string
}

// CodeLocation is the source location of a SAST/secret finding.
type CodeLocation struct {
	File        string
	StartLine   int
	EndLine     int
	StartColumn int
	EndColumn   int
	Snippet     string
}

// Dimension is one structured attribute of a finding, persisted as a
// finding_dimensions row and used for waiver matching (e.g.
// vulnerability_id, package_name, fixed_version).
type Dimension struct {
	Key   string
	Value string
}

// Fingerprint is a stable finding identifier within a project.
type Fingerprint string

// SCAFingerprint computes the SCA fingerprint from a vulnerability id and
// normalized purl.
func SCAFingerprint(vulnID, purl string) Fingerprint {
	return Fingerprint(vulnID + ":" + purl)
}

// SCALocation renders the display location of an SCA finding from the
// affected package and the scan context that observed it.
func SCALocation(packageName, installedVersion, where string) string {
	if packageName == "" {
		return where
	}
	location := packageName
	if installedVersion != "" {
		location += " " + installedVersion
	}
	if where != "" && where != packageName {
		location += " in " + where
	}
	return location
}

// CanonicalVulnID resolves the canonical vulnerability identifier. CVE identifiers
// (e.g. CVE-2024-1234) take precedence over tool-specific or ecosystem IDs (GHSA,
// PYSEC, GO, RHSA) to ensure finding identity converges across scanners (RFC 0001).
func CanonicalVulnID(primaryID string, aliases []string) string {
	primaryUpper := strings.ToUpper(strings.TrimSpace(primaryID))
	if strings.HasPrefix(primaryUpper, "CVE-") {
		return primaryUpper
	}
	for _, a := range aliases {
		aliasUpper := strings.ToUpper(strings.TrimSpace(a))
		if strings.HasPrefix(aliasUpper, "CVE-") {
			return aliasUpper
		}
	}
	return primaryID
}

// Canonical dimension-key vocabulary. These keys are the persisted
// snake_case contract shared by every scanner/watcher producer, the waiver
// matcher, and the UI. New producers must emit exactly these keys; plugin
// payloads that do not fit a canonical key belong in the namespaced
// Extensions map, never as unbounded dimension keys.
const (
	DimVulnerabilityID string = "vulnerability_id"
	DimAlias           string = "alias"
	DimPURL            string = "purl"
	DimPackageName     string = "package_name"
	DimEcosystem       string = "ecosystem"
	DimInstalledVer    string = "installed_version"
	DimFixedVersion    string = "fixed_version"
	DimRuleID          string = "rule_id"
	DimFile            string = "file"
	DimLine            string = "line"
	DimResource        string = "resource"
	DimSource          string = "source"
	// DimURL is the observed URL without query parameters or fragments:
	// identity-grade for DAST. Query keys of interest get their own
	// parameter dimension; the rest stays out of identity.
	DimURL string = "url"
	// DimParameter is one URL query/form parameter under test (name only,
	// never the value — values may carry payloads or secrets).
	DimParameter string = "parameter"
)
